package com.lmax.disruptor;
public final class SleepingWaitStrategy implements WaitStrategy {
    public SleepingWaitStrategy() {}
    public SleepingWaitStrategy(int retries) {}
    public SleepingWaitStrategy(int retries, long sleepTimeNs) {}
    @Override public long waitFor(long sequence, Sequence cursor, Sequence dependentSequence, SequenceBarrier barrier) { return dependentSequence.get(); }
    @Override public void signalAllWhenBlocking() {}
}
