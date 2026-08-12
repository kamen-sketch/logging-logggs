package org.apache.commons.compress.compressors;
import java.io.OutputStream;
public class CompressorStreamFactory {
    public OutputStream createCompressorOutputStream(String name, OutputStream out) throws CompressorException {
        throw new CompressorException("commons-compress is a stub in this no-Maven build");
    }
}
