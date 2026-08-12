import java.io.IOException;
import java.net.InetSocketAddress;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/** Fixtures for log4j-ssl-hostname-verification. Compiles against the JDK alone. */
class SslHostnameVerificationCases {

    // --- vulnerable ------------------------------------------------------

    /** No hostname verification at all: the exact shape CVE-2020-9488's class of bug takes. */
    public SSLSocket connectUnverified(SSLSocketFactory factory, String host, int port) throws IOException {
        // ruleid: log4j-ssl-hostname-verification
        SSLSocket socket = (SSLSocket) factory.createSocket();
        socket.connect(new InetSocketAddress(host, port));
        socket.startHandshake();
        return socket;
    }

    // --- safe --------------------------------------------------------------

    /** The exact fix SslSocketManager.createSocket() uses. */
    public SSLSocket connectVerified(SSLSocketFactory factory, String host, int port) throws IOException {
        // ok: log4j-ssl-hostname-verification
        SSLSocket socket = (SSLSocket) factory.createSocket();
        socket.connect(new InetSocketAddress(host, port));
        SSLParameters params = socket.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS");
        socket.setSSLParameters(params);
        socket.startHandshake();
        return socket;
    }

    // --- regression: conditional hardening ----------------------------------

    /**
     * Hostname verification is applied only when `strict` is true, but
     * startHandshake() always runs -- when strict is false, this is exactly
     * as vulnerable as connectUnverified() above. Same documented limitation
     * as log4j-xxe's conditionallyHardened and
     * log4j-unsafe-deserialization's readConditionallyFiltered: "..." in
     * pattern-not matches straight through an untaken if-branch. Marked
     * todoruleid rather than ruleid from the start this time, learned from
     * those two rules rather than discovering it again the hard way.
     */
    public SSLSocket connectConditionallyVerified(SSLSocketFactory factory, String host, int port, boolean strict)
            throws IOException {
        // todoruleid: log4j-ssl-hostname-verification
        SSLSocket socket = (SSLSocket) factory.createSocket();
        socket.connect(new InetSocketAddress(host, port));
        if (strict) {
            SSLParameters params = socket.getSSLParameters();
            params.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(params);
        }
        socket.startHandshake();
        return socket;
    }
}
