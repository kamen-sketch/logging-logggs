package com.lmax.disruptor;
public interface WaitStrategy {
    long waitFor(long sequence, Sequence cursor, Sequence dependentSequence, SequenceBarrier barrier)
        throws AlertException, InterruptedException, TimeoutException;
    void signalAllWhenBlocking();
}
