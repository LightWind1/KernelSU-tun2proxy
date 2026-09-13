import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

// Device acceptance probe: uses the ROM's default TrustManager without bypasses.
public final class HTTPSProbe {
    public static void main(String[] args) throws Exception {
        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(args[0], Integer.parseInt(args[1])));
        HttpsURLConnection connection = (HttpsURLConnection)new URL(
            "https://example.com/?tun2proxy_test=android_system_ca").openConnection(proxy);
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(10000);
        try {
            System.out.println("HTTPS_STATUS=" + connection.getResponseCode());
            System.out.println("PEER=" + connection.getPeerPrincipal().getName());
        } catch (Exception e) {
            System.out.println("HTTPS_FAILURE=" + e.getClass().getSimpleName());
            System.exit(1);
        } finally { connection.disconnect(); }
    }
}
