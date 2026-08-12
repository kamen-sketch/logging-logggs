import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;

/** Fixtures for log4j-unsafe-deserialization. Compiles against the JDK alone. */
class UnsafeDeserializationCases {

    // --- vulnerable ------------------------------------------------------

    /** CVE-2019-17571: a serialized log event read straight off a socket. */
    public Object readFromSocket(Socket socket) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        // ruleid: log4j-unsafe-deserialization
        return ois.readObject();
    }

    /** Same sink reached from an accepted connection. */
    public Object readFromServerSocket(ServerSocket server) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(server.accept().getInputStream());
        // ruleid: log4j-unsafe-deserialization
        return ois.readObject();
    }

    /** A caller-supplied stream is not trusted either. */
    public Object readFromParameter(InputStream in) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(in);
        // ruleid: log4j-unsafe-deserialization
        return ois.readObject();
    }

    /** Wrapping bytes in a ByteArrayInputStream changes nothing. */
    public Object readFromBytes(byte[] payload) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
        // ruleid: log4j-unsafe-deserialization
        return ois.readObject();
    }

    // --- safe ------------------------------------------------------------

    /** An ObjectInputFilter constrains the reachable class graph. */
    public Object readFiltered(InputStream in) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(in);
        ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
                "org.apache.logging.log4j.**;java.base/*;!*"));
        // ok: log4j-unsafe-deserialization
        return ois.readObject();
    }

    /** Deserializing a constant, in-process payload -- never tainted to begin with. */
    public Object readTrustedConstant() throws IOException, ClassNotFoundException {
        byte[] trusted = new byte[] {(byte) 0xAC, (byte) 0xED};
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(trusted));
        // ok: log4j-unsafe-deserialization
        return ois.readObject();
    }
}
