package org.osgi.framework;
public final class AdaptPermission extends java.security.BasicPermission {
    private static final long serialVersionUID = 1L;
    public static final String ADAPT = "adapt";
    public AdaptPermission(String filter, String actions) { super(filter, actions); }
    public AdaptPermission(String adaptClass, Bundle adaptableBundle, String actions) { super(adaptClass, actions); }
}
