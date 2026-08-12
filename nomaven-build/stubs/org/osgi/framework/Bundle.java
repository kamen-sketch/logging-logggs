package org.osgi.framework;
public interface Bundle {
    int UNINSTALLED = 0x1, INSTALLED = 0x2, RESOLVED = 0x4,
        STARTING = 0x8, STOPPING = 0x10, ACTIVE = 0x20;
    int getState();
    long getBundleId();
    String getSymbolicName();
    BundleContext getBundleContext();
    <A> A adapt(Class<A> type);
    java.net.URL getEntry(String path);
    java.util.Enumeration<String> getEntryPaths(String path);
    Class<?> loadClass(String name) throws ClassNotFoundException;
}
