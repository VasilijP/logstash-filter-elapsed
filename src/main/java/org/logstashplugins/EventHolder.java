package org.logstashplugins;

import co.elastic.logstash.api.Event;

import java.time.Duration;
import java.time.Instant;

public class EventHolder
{	
	public EventHolder(Event e)
	{
		this.e = e;
		this.i = Instant.now();
	}
	
	public boolean isExpired(int expirationSeconds)
	{
		return Duration.between(this.i, Instant.now()).getSeconds() > expirationSeconds;
	}

	public Event getE()
	{
		return e;
	}

	private Event e;
	
	private Instant i;
}
