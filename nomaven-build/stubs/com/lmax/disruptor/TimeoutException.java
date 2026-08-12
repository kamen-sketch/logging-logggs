package com.lmax.disruptor;
public final class TimeoutException extends Exception {
    private static final long serialVersionUID = 1L;
    public static final TimeoutException INSTANCE = new TimeoutException();
    private TimeoutException() { super(null, null, false, false); }
}
