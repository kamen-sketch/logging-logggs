package org.apache.commons.compress.utils;
import java.io.*;
public final class IOUtils {
    private IOUtils() {}
    public static long copy(InputStream in, OutputStream out) throws IOException { return in.transferTo(out); }
    public static long copy(InputStream in, OutputStream out, int bufferSize) throws IOException { return in.transferTo(out); }
}
