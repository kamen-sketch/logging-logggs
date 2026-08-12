package org.osgi.framework.wiring;
import java.net.URL;
import java.util.Collection;
import java.util.List;
public interface BundleWiring {
    int LISTRESOURCES_RECURSE = 0x1, LISTRESOURCES_LOCAL = 0x2;
    Collection<String> listResources(String path, String filePattern, int options);
    List<URL> findEntries(String path, String filePattern, int options);
    List<BundleWire> getRequiredWires(String namespace);
    List<BundleWire> getProvidedWires(String namespace);
    ClassLoader getClassLoader();
    org.osgi.framework.Bundle getBundle();
    BundleRevision getRevision();
}
