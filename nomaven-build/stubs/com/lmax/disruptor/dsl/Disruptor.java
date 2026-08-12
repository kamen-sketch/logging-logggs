package com.lmax.disruptor.dsl;
import com.lmax.disruptor.*;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
/** Compile-time stub -- see RingBuffer. */
public final class Disruptor<T> {
    public Disruptor(EventFactory<T> f, int ringBufferSize, ThreadFactory tf, ProducerType pt, WaitStrategy ws) { throw nope(); }
    public Disruptor(EventFactory<T> f, int ringBufferSize, ThreadFactory tf) { throw nope(); }
    private static UnsupportedOperationException nope() {
        return new UnsupportedOperationException(
            "LMAX Disruptor is a stub in this no-Maven build; async logging is unavailable.");
    }
    @SafeVarargs public final void handleEventsWith(EventHandler<? super T>... handlers) { throw nope(); }
    public void setDefaultExceptionHandler(ExceptionHandler<? super T> h) { throw nope(); }
    public RingBuffer<T> getRingBuffer() { throw nope(); }
    public RingBuffer<T> start() { throw nope(); }
    public void shutdown() { throw nope(); }
    public void shutdown(long timeout, TimeUnit unit) throws TimeoutException { throw nope(); }
    public void halt() { throw nope(); }
    public boolean hasBacklog() { throw nope(); }
    public void publishEvent(EventTranslator<T> t) { throw nope(); }
    public <A, B> void publishEvent(EventTranslatorTwoArg<T, A, B> t, A a, B b) { throw nope(); }
    public void publishEvent(EventTranslatorVararg<T> t, Object... args) { throw nope(); }
}
