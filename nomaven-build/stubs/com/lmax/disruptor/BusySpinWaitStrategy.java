package com.lmax.disruptor;
public final class BusySpinWaitStrategy implements WaitStrategy {
    @Override public long waitFor(long sequence, Sequence cursor, Sequence dependentSequence, SequenceBarrier barrier) { return dependentSequence.get(); }
    @Override public void signalAllWhenBlocking() {}
}
