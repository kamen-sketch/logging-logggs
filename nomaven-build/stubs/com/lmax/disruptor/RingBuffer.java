package com.lmax.disruptor;
import java.util.concurrent.ThreadFactory;
/** Compile-time stub. Async logging is NOT functional against these stubs --
 *  every runtime entry point fails loudly rather than silently dropping events. */
public final class RingBuffer<E> {
    private RingBuffer() {}
    private static UnsupportedOperationException nope() {
        return new UnsupportedOperationException(
            "LMAX Disruptor is a stub in this no-Maven build; async logging is unavailable.");
    }
    public static <E> RingBuffer<E> createSingleProducer(EventFactory<E> f, int sz, WaitStrategy w) { throw nope(); }
    public static <E> RingBuffer<E> createMultiProducer(EventFactory<E> f, int sz, WaitStrategy w) { throw nope(); }
    public int getBufferSize() { throw nope(); }
    public long remainingCapacity() { throw nope(); }
    public long getCursor() { throw nope(); }
    public long getMinimumGatingSequence() { throw nope(); }
    public boolean hasAvailableCapacity(int n) { throw nope(); }
    public long next() { throw nope(); }
    public E get(long sequence) { throw nope(); }
    public void publish(long sequence) { throw nope(); }
    public void publishEvent(EventTranslator<E> t) { throw nope(); }
    public <A, B> void publishEvent(EventTranslatorTwoArg<E, A, B> t, A a, B b) { throw nope(); }
    public void publishEvent(EventTranslatorVararg<E> t, Object... args) { throw nope(); }
    public boolean tryPublishEvent(EventTranslator<E> t) { throw nope(); }
    public <A, B> boolean tryPublishEvent(EventTranslatorTwoArg<E, A, B> t, A a, B b) { throw nope(); }
    public boolean tryPublishEvent(EventTranslatorVararg<E> t, Object... args) { throw nope(); }
    public void addGatingSequences(Sequence... s) { throw nope(); }
}
