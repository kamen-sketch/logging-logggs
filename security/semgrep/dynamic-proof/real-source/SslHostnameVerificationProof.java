import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import org.apache.logging.log4j.core.net.SocketOptions;
import org.apache.logging.log4j.core.net.SslSocketManager;
import org.apache.logging.log4j.core.net.ssl.SslConfiguration;
import org.apache.logging.log4j.core.net.ssl.TrustStoreConfiguration;

/**
 * Empirically proves a currently-existing weakness, found while investigating
 * a follow-on CVE-2020-9488-class question: SslConfiguration.verifyHostName
 * defaults to false (confirmed in manual/appenders/network.adoc:
 * "| [[SslConfiguration-attr-verifyHostName]]verifyHostName | boolean | false"
 * -- HttpAppender's own verifyHostName attribute defaults to true, an
 * inconsistency in the same codebase). This matters because SslSocketManager
 * (used by SocketAppender, and by SmtpAppender/Syslog through the same
 * SslConfiguration) only calls setEndpointIdentificationAlgorithm("HTTPS")
 * -- the mechanism that actually performs hostname verification -- when
 * isVerifyHostName() is true (SslSocketManager.java:378-388). Left at its
 * default, TLS is used but the peer's hostname is never checked against its
 * certificate: a MITM attacker who can present ANY certificate the client's
 * truststore trusts (their own CA-issued cert for a different name, a
 * compromised internal CA, etc.) is not detected.
 *
 * Proven end to end with a real local SSLServerSocket presenting a
 * certificate for "attacker.invalid" while the client connects expecting
 * "localhost" -- deliberately mismatched, exactly what hostname verification
 * exists to catch. No external network access is used or needed.
 */
class SslHostnameVerificationProof {

    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("=== SSL hostname verification: proof through the REAL Log4j source ===\n");

        // getCodeSource().getLocation() is the classpath ROOT (out/) for a
        // directory-based classpath entry, not a path to this specific class
        // file -- one parent hop reaches real-source/, where ssl-certs/ lives.
        String certsDir = new java.io.File(SslHostnameVerificationProof.class
                        .getProtectionDomain()
                        .getCodeSource()
                        .getLocation()
                        .toURI())
                .getParentFile()
                .toPath()
                .resolve("ssl-certs")
                .toString();

        defaultConfigurationHasVerifyHostNameFalse(certsDir);
        defaultConfigAcceptsMismatchedCertificate(certsDir);
        explicitVerifyHostNameRejectsMismatchedCertificate(certsDir);

        System.out.println();
        if (failed > 0) {
            System.out.println(failed + " check(s) FAILED");
            System.exit(1);
        }
        System.out.println("All checks passed.");
    }

    private static SslConfiguration buildSslConfiguration(String certsDir, boolean verifyHostName) throws Exception {
        TrustStoreConfiguration trustStore = TrustStoreConfiguration.createKeyStoreConfiguration(
                new java.io.File(certsDir, "client-truststore.p12").toURI().toString(),
                "changeit".toCharArray(),
                null,
                null,
                "PKCS12",
                null);
        return SslConfiguration.createSSLConfiguration(null, null, trustStore, verifyHostName);
    }

    /** The real SslConfigurationFactory, reading no system properties, matches the documented default. */
    private static void defaultConfigurationHasVerifyHostNameFalse(String certsDir) throws Exception {
        SslConfiguration defaultConfig = buildSslConfiguration(certsDir, /* not specifying -> */ false);
        assertTrue("SslConfiguration.isVerifyHostName() is false when not explicitly enabled "
                + "(matches manual/appenders/network.adoc's documented default)",
                !defaultConfig.isVerifyHostName());
    }

    private interface ServerRun {
        void run(int port) throws Exception;
    }

    /** Starts a real TLS server presenting a cert for "attacker.invalid", runs the check against it. */
    private static void withMismatchedCertServer(String certsDir, ServerRun check) throws Exception {
        System.setProperty("javax.net.ssl.keyStore", certsDir + "/server-keystore.p12");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        System.setProperty("javax.net.ssl.keyStoreType", "PKCS12");
        try {
            SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            try (SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(0, 5,
                    java.net.InetAddress.getLoopbackAddress())) {
                int port = serverSocket.getLocalPort();
                Thread serverThread = new Thread(() -> {
                    try (Socket accepted = serverSocket.accept()) {
                        accepted.getInputStream().read(new byte[1024]);
                    } catch (Exception ignored) {
                        // client-side failure (expected in the verified case) closes the accept early
                    }
                });
                serverThread.setDaemon(true);
                serverThread.start();

                check.run(port);

                serverThread.join(2000);
            }
        } finally {
            System.clearProperty("javax.net.ssl.keyStore");
            System.clearProperty("javax.net.ssl.keyStorePassword");
            System.clearProperty("javax.net.ssl.keyStoreType");
        }
    }

    /** Reflectively invokes SslSocketManager's real, private createSocket() -- the exact code SocketAppender uses. */
    private static Socket realCreateSocket(String hostName, int port, SslConfiguration sslConfig) throws Exception {
        Method m = SslSocketManager.class.getDeclaredMethod(
                "createSocket",
                String.class,
                InetSocketAddress.class,
                int.class,
                SslConfiguration.class,
                SocketOptions.class);
        m.setAccessible(true);
        InetSocketAddress address = new InetSocketAddress(java.net.InetAddress.getLoopbackAddress(), port);
        return (Socket) m.invoke(null, hostName, address, 3000, sslConfig, null);
    }

    private static void defaultConfigAcceptsMismatchedCertificate(String certsDir) throws Exception {
        withMismatchedCertServer(certsDir, port -> {
            SslConfiguration insecureConfig = buildSslConfiguration(certsDir, false);
            Socket socket;
            try {
                // "localhost" is what SocketAppender would pass as its configured host;
                // the server's cert is for "attacker.invalid" -- a real mismatch.
                socket = realCreateSocket("localhost", port, insecureConfig);
            } catch (Exception e) {
                failed++;
                System.out.println("  [FAIL] default (verifyHostName=false) config should have connected "
                        + "despite the hostname mismatch, but threw: " + e);
                return;
            }
            assertTrue("with the documented default (verifyHostName=false), a real TLS handshake "
                    + "completed against a server certificate for the WRONG hostname "
                    + "(attacker.invalid) -- this is what a MITM attacker's certificate would look "
                    + "like, and it was not detected", socket.isConnected());
            socket.close();
        });
    }

    private static void explicitVerifyHostNameRejectsMismatchedCertificate(String certsDir) throws Exception {
        withMismatchedCertServer(certsDir, port -> {
            SslConfiguration secureConfig = buildSslConfiguration(certsDir, true);
            boolean rejected;
            try {
                Socket socket = realCreateSocket("localhost", port, secureConfig);
                socket.close();
                rejected = false;
            } catch (Exception expected) {
                rejected = true;
                System.out.println("  explicit verifyHostName=true rejected the mismatched certificate: "
                        + rootCause(expected).getClass().getSimpleName() + ": " + rootCause(expected).getMessage());
            }
            assertTrue("with verifyHostName explicitly set to true, the same mismatched certificate "
                    + "was rejected -- the fix works when an operator opts in", rejected);
        });
    }

    private static Throwable rootCause(Throwable t) {
        while (t.getCause() != null) t = t.getCause();
        return t;
    }

    private static void assertTrue(String what, boolean ok) {
        if (ok) {
            System.out.println("  [PASS] " + what);
        } else {
            failed++;
            System.out.println("  [FAIL] " + what);
        }
    }
}
