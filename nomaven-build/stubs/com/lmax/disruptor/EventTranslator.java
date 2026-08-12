package com.lmax.disruptor;
public interface EventTranslator<T> { void translateTo(T event, long sequence); }
