package com.lmax.disruptor;
import java.util.concurrent.TimeUnit;
public final class TimeoutBlockingWaitStrategy implements WaitStrategy {
    public TimeoutBlockingWaitStrategy(long timeout, TimeUnit units) {}
    @Override public long waitFor(long sequence, Sequence cursor, Sequence dependentSequence, SequenceBarrier barrier) { return dependentSequence.get(); }
    @Override public void signalAllWhenBlocking() {}
}
