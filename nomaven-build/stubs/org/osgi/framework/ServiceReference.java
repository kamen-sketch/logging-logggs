package org.osgi.framework;
public interface ServiceReference<S> extends Comparable<Object> { Bundle getBundle(); Object getProperty(String key); }
