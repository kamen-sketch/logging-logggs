package com.lmax.disruptor;
public interface EventTranslatorVararg<T> { void translateTo(T event, long sequence, Object... args); }
