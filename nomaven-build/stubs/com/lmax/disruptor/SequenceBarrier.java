package com.lmax.disruptor;
public interface SequenceBarrier {
    long waitFor(long sequence) throws AlertException, InterruptedException, TimeoutException;
    long getCursor(); boolean isAlerted(); void alert(); void clearAlert(); void checkAlert() throws AlertException;
}
