import java.net.URL;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import javax.net.ssl.HttpsURLConnection;

/**
 * Run by javafix inside each Java runtime it checks (Java 8+, compiled with --release 8).
 * Opens one HTTPS connection per host argument with the runtime's default trust settings and prints one line:
 *   ACCEPTED <host> <http status>   the certificate chain was trusted
 *   REJECTED <host> <exception>     the chain was refused by certificate validation
 *   ERROR <host> <exception>        anything else (no network, DNS, timeout, TLS protocol)
 */
public class JavafixProbe {
    public static void main(String[] args) {
        for (String host : args) {
            try {
                HttpsURLConnection c = (HttpsURLConnection) new URL("https://" + host + "/").openConnection();
                c.setConnectTimeout(10000);
                c.setReadTimeout(10000);
                c.setRequestMethod("HEAD");
                c.setInstanceFollowRedirects(false);
                int code = c.getResponseCode();
                c.disconnect();
                System.out.println("ACCEPTED " + host + " " + code);
            } catch (Exception e) {
                System.out.println((isCertificateFailure(e) ? "REJECTED " : "ERROR ") + host + " " + rootName(e));
            }
        }
    }

    private static boolean isCertificateFailure(Throwable t) {
        for (; t != null; t = t.getCause()) {
            if (t instanceof CertPathValidatorException || t instanceof CertificateException
                    || t.getClass().getName().endsWith("SunCertPathBuilderException")) {
                return true;
            }
        }
        return false;
    }

    private static String rootName(Throwable t) {
        while (t.getCause() != null) {
            t = t.getCause();
        }
        return t.getClass().getSimpleName();
    }
}
