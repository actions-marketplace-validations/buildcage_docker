// Proves the JVM already in the base image trusts the inspect engine's proxy CA
// in-step. The JVM reads its trusted roots only from its own keystore, so
// without the wrapper adding the CA there for the step, connect() fails with an
// SSLHandshakeException (PKIX path building failed) before any status returns. A
// status coming back at all is the proof; what it is does not matter, since the
// TLS handshake is with the proxy that re-signed the connection.
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

public class HttpsCheck {
    public static void main(String[] args) throws Exception {
        HttpsURLConnection c = (HttpsURLConnection) new URL(args[0]).openConnection();
        c.setConnectTimeout(15000);
        c.setReadTimeout(15000);
        c.connect();
        System.out.println("handshake ok, status=" + c.getResponseCode());
        c.disconnect();
    }
}
