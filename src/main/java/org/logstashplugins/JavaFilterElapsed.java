package org.logstashplugins;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.logging.log4j.Logger;

import co.elastic.logstash.api.Configuration;
import co.elastic.logstash.api.Context;
import co.elastic.logstash.api.Event;
import co.elastic.logstash.api.Filter;
import co.elastic.logstash.api.FilterMatchListener;
import co.elastic.logstash.api.LogstashPlugin;
import co.elastic.logstash.api.PluginConfigSpec;
import co.elastic.logstash.api.PluginHelper;

/**
   The elapsed filter collects all the "start events". If two, or more, "start events" have the same ID, only the first one is recorded, the others are discarded.

	When an "end event" matching a previously collected "start event" is received, there is a match. The configuration property new_event_on_match tells where to insert the elapsed information: they can be added to the "end event" or a new "match event" can be created. Both events store the following information:
	
	- the tags elapsed and elapsed_match
	- the field elapsed_time with the difference, in seconds, between the two events timestamps
	- an ID filed with the task ID
	- the field elapsed_timestamp_start with the timestamp of the start event
	
	If the "end event" does not arrive before "timeout" seconds, the "start event" is discarded and an "expired event" is generated. This event contains:
	
	- the tags elapsed and elapsed_expired_error 
	- a field called elapsed_time with the age, in seconds, of the "start event"
	- an ID filed with the task ID
	- the field elapsed_timestamp_start with the timestamp of the "start event"
 * 
 * @author Peter
 *
 */
@LogstashPlugin(name = "java_filter_elapsed")
public class JavaFilterElapsed implements Filter
{
	private static AtomicInteger instanceCounter = new AtomicInteger();	

	// which field holds the hash (field used to pair start and end event)
	public static final PluginConfigSpec<String> UNIQUE_ID_FIELD_CONFIG = PluginConfigSpec.stringSetting("unique_id_field", "event.hash");
    
	// how to recognize start events? they are tagged with start tag
    public static final PluginConfigSpec<String> START_TAG_CONFIG = PluginConfigSpec.stringSetting("start_tag", "encoding_start");
    
    // end tag
    public static final PluginConfigSpec<String> END_TAG_CONFIG = PluginConfigSpec.stringSetting("end_tag", "encoding_end");
    
    // how to pair incoming end event? take first start event, or the last one if there is more?
    public static final PluginConfigSpec<Boolean> PAIR_ORDER_FIRST = PluginConfigSpec.booleanSetting("pair_first", true);
    
    // how long is the unpaired event (start or end one) kept in our cache?
    public static final PluginConfigSpec<Long> TIMEOUT_SECONDS_CONFIG = PluginConfigSpec.numSetting("timeout", 10);
        
    private Logger log;
    private Integer instanceNumber;
    private String id;
    private String uniqueHashField;
    private String startTag;
    private String endTag;
    private boolean pairFirst;
    private int timeoutSeconds;
    
    private final Map<String, Deque<EventHolder>> startEvents;
    private final Map<String, EventHolder> endEvents;
    
    public JavaFilterElapsed(String id, Configuration config, Context context)
    {
	    	this.instanceNumber = instanceCounter.addAndGet(1);	    	
	    	startEvents = new HashMap<String, Deque<EventHolder>>();
	    	endEvents = new HashMap<String, EventHolder>();
	    	
	        this.id = id;
	        this.uniqueHashField = config.get(UNIQUE_ID_FIELD_CONFIG);
	        this.startTag = config.get(START_TAG_CONFIG);
	        this.endTag = config.get(END_TAG_CONFIG);
	        this.pairFirst = config.get(PAIR_ORDER_FIRST);
	        this.timeoutSeconds = config.get(TIMEOUT_SECONDS_CONFIG).intValue();
	        
	        this.log = context.getLogger(this);
	        log.info(this.toString()+" is created (timeout: "+timeoutSeconds+", pairFirst: "+pairFirst+", start tag: "+startTag+", end tag: "+endTag+", hash field: "+uniqueHashField+").");
    }
    
    @Override
    public Collection<Event> filter(Collection<Event> eventsCollection, FilterMatchListener matchListener)
    {
		try
		{
			List<Event> events = new ArrayList<Event>(eventsCollection); // additional list which will contain same instances of events like eventsCollection, but sorted chronologically
    		if (eventsCollection.size() > 0) // pipeline gets triggered periodically also when there are no incoming events, btw this allows us to process timeouts on enlisted events
        	{
    			log.debug("Filtering "+events.size()+" events, start event keys cached: "+startEvents.size()+", end event keys cached: "+endEvents.size()+".");
        	}
		    	
	    	synchronized(startEvents)
	    	{
		    	
		        for (Event e : events)
		        {
		        	if (isStartEvent(e))
		        	{
		        		String uniqueId = e.getField(uniqueHashField).toString();
		        		log.debug(this.toString()+" Found START event: "+uniqueId);
		        		
		        		if (!startEvents.containsKey(uniqueId)) // ensure there is a place to store new EventHolder
		        		{
		        			startEvents.put(uniqueId, new ArrayDeque<EventHolder>());
		        		}
		        		
		        		if (pairFirst) // always pair first start encountered (like queue)
		        		{
		        			startEvents.get(uniqueId).addLast(new EventHolder(e));
		        		}
		        		else // always pair last start encountered (like with stack)
		        		{
		        			startEvents.get(uniqueId).addFirst(new EventHolder(e));
		        		}
		        		
		        		matchListener.filterMatched(e);		        		
		        	}		        	
		        	else if (isEndEvent(e))
		        	{	        		
		        		String uniqueId = e.getField(uniqueHashField).toString();
		        		log.debug(this.toString()+" Found END event: "+uniqueId);
		        		
		        		if (startEvents.containsKey(uniqueId)) // we have a matching start event - main flow: pair events, calculate duration, remove start event
			        	{
			        		Event startEvent = startEvents.get(uniqueId).removeFirst().getE();
			        		double elapsedTime = calculateDurationSeconds(startEvent.getField("@timestamp").toString(), e.getField("@timestamp").toString());	        	
			        		e.setField("elapsed_time", elapsedTime);
			        		e.tag("elapsed");
			        		e.tag("elapsed_match");
			        		matchListener.filterMatched(e);
			        		if (startEvents.get(uniqueId).isEmpty()) { startEvents.remove(uniqueId); }
			        		log.debug(this.toString()+" calculated (A) duration for event: "+uniqueId);
			        	}
		        		else if (endEvents.containsKey(uniqueId)) // check for colliding end events
		        		{
		        			log.error("End event collision detected for "+uniqueHashField+" field: "+uniqueId);
		        		}
		        		else // add end event to collection for future matching and remove from event stream for now
		        		{
		        			eventsCollection.remove(e);
		        			endEvents.put(uniqueId, new EventHolder(e));
		        		}
		        	}
		        }
		           
		        Set<String> keySet = new HashSet<String>(endEvents.keySet());
		        for(String eventId : keySet) // go through end events and find complete events and timed out events
		        {
		        	EventHolder endEventHolder = endEvents.get(eventId);
		        	Event endEvent = endEventHolder.getE();
		        	
		        	if (startEvents.containsKey(eventId)) // we have a matching start event - main flow plan B (end event and start event are swapped)
		        	{
		        		Event startEvent = startEvents.get(eventId).removeFirst().getE();
		        		double elapsedTime = calculateDurationSeconds(startEvent.getField("@timestamp").toString(), endEvent.getField("@timestamp").toString());	        	
		        		endEvent.setField("elapsed_time", elapsedTime);
		        		endEvent.tag("elapsed");
		        		endEvent.tag("elapsed_match");	        		
		        		eventsCollection.add(endEvent);
		        		if (startEvents.get(eventId).isEmpty()) { startEvents.remove(eventId); }
		        		endEvents.remove(eventId);
		        		matchListener.filterMatched(endEvent);
		        		log.debug(this.toString()+" calculated (B) duration for event: "+eventId);
		        	}
		        	else if (endEventHolder.isExpired(timeoutSeconds)) // we have a timed out event
		        	{	        		
		        		endEvent.tag("elapsed");
		        		endEvent.tag("elapsed_end_without_start");
		        		eventsCollection.add(endEvent);
		        		endEvents.remove(eventId);
		        		matchListener.filterMatched(endEvent);
		        		log.debug(this.toString()+" End event timed out: "+eventId);
		        	}
		        }
		        
		        // go through start events and find timed out events
		        keySet = new HashSet<String>(startEvents.keySet());
				for(String eventId : keySet)
		        {
		        	if (startEvents.get(eventId).peekFirst().isExpired(timeoutSeconds))
		        	{
		        		Event startEvent = startEvents.get(eventId).removeFirst().getE();
		        		if (startEvents.get(eventId).isEmpty()) { startEvents.remove(eventId); }
		        			        		
		        		Event newEvent = new org.logstash.Event();
		        		
		        		// If the "end event" does not arrive before "timeout" seconds, the "start event" is discarded(from filter maintained collection) and an "expired event" is generated.
		        		// This event contains:
		        		newEvent.tag("elapsed"); // the tags elapsed and elapsed_expired_error
		        		newEvent.tag("elapsed_expired_error");
		        		newEvent.setField("elapsed_time", timeoutSeconds); // a field called elapsed_time with the age, in seconds, of the "start event"
		        		newEvent.setField("@timestamp", startEvent.getField("@timestamp")); // the field elapsed_timestamp_start with the timestamp of the "start event"
		        		newEvent.setField(uniqueHashField, startEvent.getField(uniqueHashField));
		        		
		        		// example:
		        		// { "tags": ["elapsed", "elapsed_expired_error"],
		        	    //   "@timestamp": "2019-12-05T22:17:31.970Z",
		        	    //   "event.hash": "6b0cf211019c101e9166598cc45433ba1fb33d5a2bf972b1cefe31eb66b929da",
		        	    //   "elapsed_time": 600 }
		        		
		        		events.add(newEvent);
		        		matchListener.filterMatched(newEvent);
		        		log.debug("Start event timed out: "+eventId);
		        	}
		        }
		    }
		}
		catch (Exception e)
		{
			log.error("Error while parsing events: "+e.getMessage(), e);
		}    	
    	
        return eventsCollection;
    }

	private double calculateDurationSeconds(String thisEventTimestamp, String lastEventTimestamp)
	{
		Instant from = Instant.parse(thisEventTimestamp);
		Instant to = Instant.parse(lastEventTimestamp);
		
		long duration = Duration.between(from, to).toMillis();
		//log.debug(this.toString()+" calculated duration from "+thisEventTimestamp+" to "+lastEventTimestamp+" as "+duration+"ms.");
		return duration*0.001;
	}

	private boolean isStartEvent(Event event)
    {
    	return containsTag(event, startTag);
    }
    
    private boolean isEndEvent(Event event)
    {
    	return containsTag(event, endTag);
    }

    private boolean containsTag(Event event, String tag)
    {
    	Object tags = event.getField("tags");
    	if (tags instanceof List)
    	{    		
            return ((List<String>)tags).contains(tag);
    	}    	
    	return false;
	}

    // should return a list of all configuration options for this plugin
	@Override
    public Collection<PluginConfigSpec<?>> configSchema()
    {
		return PluginHelper.commonFilterSettings(Arrays.asList(UNIQUE_ID_FIELD_CONFIG, 
												                START_TAG_CONFIG,
												                END_TAG_CONFIG,
												                PAIR_ORDER_FIRST,
												                TIMEOUT_SECONDS_CONFIG));
    }
	
    @Override
	public String toString()
    {
		return "JavaFilterElapsed #"+instanceNumber+" id:"+id;
	}

    @Override
    public String getId()
    {
        return this.id;
    }
}
