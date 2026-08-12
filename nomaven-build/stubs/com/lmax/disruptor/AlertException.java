package com.lmax.disruptor;
public final class AlertException extends Exception {
    private static final long serialVersionUID = 1L;
    public static final AlertException INSTANCE = new AlertException();
    private AlertException() { super(null, null, false, false); }
}
