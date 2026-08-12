package org.osgi.framework;
public class InvalidSyntaxException extends Exception {
    private static final long serialVersionUID = 1L;
    private final String filter;
    public InvalidSyntaxException(String msg, String filter) { super(msg); this.filter = filter; }
    public String getFilter() { return filter; }
}
