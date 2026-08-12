package org.osgi.framework;
public class BundleEvent {
    public static final int INSTALLED=0x1, STARTED=0x2, STOPPED=0x4, UPDATED=0x8,
        UNINSTALLED=0x10, RESOLVED=0x20, UNRESOLVED=0x40, STARTING=0x80, STOPPING=0x100, LAZY_ACTIVATION=0x200;
    private final int type; private final Bundle bundle;
    public BundleEvent(int type, Bundle bundle) { this.type=type; this.bundle=bundle; }
    public int getType() { return type; }
    public Bundle getBundle() { return bundle; }
}
