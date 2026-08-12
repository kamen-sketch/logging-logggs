package com.lmax.disruptor;
public class Sequence {
    private volatile long value;
    public Sequence() { this(-1L); }
    public Sequence(long initial) { this.value = initial; }
    public long get() { return value; }
    public void set(long v) { this.value = v; }
    public void setVolatile(long v) { this.value = v; }
    public boolean compareAndSet(long e, long n) { if (value==e) { value=n; return true; } return false; }
    public long incrementAndGet() { return ++value; }
    public long addAndGet(long i) { return value += i; }
}
