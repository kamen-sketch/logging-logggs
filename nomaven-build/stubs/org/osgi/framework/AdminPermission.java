package org.osgi.framework;
public final class AdminPermission extends java.security.BasicPermission {
    private static final long serialVersionUID = 1L;
    public static final String CLASS = "class";
    public static final String METADATA = "metadata";
    public static final String RESOURCE = "resource";
    public static final String CONTEXT = "context";
    public AdminPermission() { super("*", "*"); }
    public AdminPermission(String filter, String actions) { super(filter, actions); }
    public AdminPermission(Bundle bundle, String actions) { super("(id=*)", actions); }
}
