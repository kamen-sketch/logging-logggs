package org.osgi.framework;
import java.util.Collection;
public interface BundleContext {
    Bundle getBundle();
    Bundle[] getBundles();
    <S> Collection<ServiceReference<S>> getServiceReferences(Class<S> clazz, String filter) throws InvalidSyntaxException;
    <S> S getService(ServiceReference<S> reference);
    <S> ServiceRegistration<S> registerService(Class<S> clazz, S service, java.util.Dictionary<String,?> props);
    void addBundleListener(BundleListener listener);
    void removeBundleListener(BundleListener listener);
}
