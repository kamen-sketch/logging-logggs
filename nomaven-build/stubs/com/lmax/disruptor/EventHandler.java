package com.lmax.disruptor;
public interface EventHandler<T> { void onEvent(T event, long sequence, boolean endOfBatch) throws Exception; }
