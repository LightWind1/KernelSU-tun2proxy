import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

// Uses this ROM's CertificateFactory and AndroidCAStore, not a bundled TLS library.
public final class CertificateProbe {
    public static void main(String[] args) {
        boolean parsed = false, trusted = false, signature = false;
        String provider = "";
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            provider = factory.getProvider().getName();
            X509Certificate cert;
            try (FileInputStream in = new FileInputStream(args[0])) {
                cert = (X509Certificate)factory.generateCertificate(in);
            }
            parsed = true;
            try { cert.verify(cert.getPublicKey()); signature = true; } catch (Throwable ignored) {}
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] expected = digest.digest(cert.getEncoded());
            KeyStore store = KeyStore.getInstance("AndroidCAStore");
            store.load(null);
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (!alias.startsWith("system:")) continue;
                java.security.cert.Certificate candidate = store.getCertificate(alias);
                if (candidate != null && MessageDigest.isEqual(expected, digest.digest(candidate.getEncoded()))) {
                    trusted = true; break;
                }
            }
            System.out.println("{\"parsed\":" + parsed + ",\"signatureValid\":" + signature + ",\"trusted\":" + trusted +
                ",\"provider\":\"" + provider.replaceAll("[^A-Za-z0-9_.-]", "") + "\"}");
        } catch (Throwable e) {
            // Never echo file content, secrets, or arbitrary exception strings.
            System.out.println("{\"parsed\":" + parsed + ",\"trusted\":false,\"error\":\"" +
                e.getClass().getSimpleName() + "\"}");
        }
    }
}
