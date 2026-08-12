package org.osgi.framework;
public interface ServiceRegistration<S> { ServiceReference<S> getReference(); void unregister(); }
