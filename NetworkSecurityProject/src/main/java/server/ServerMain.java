package server;

import java.util.concurrent.Executors;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.io.*;
import java.lang.reflect.Type;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;

import com.sun.net.httpserver.HttpsServer;
import java.security.*;
import javax.net.ssl.*;

public class ServerMain {

    public static void main(String[] args) throws Exception {
        DBHelper.initialize(); // Khởi tạo kết nối database

        // Tạo HTTPS server chạy ở port 8443
        HttpsServer server = HttpsServer.create(new InetSocketAddress(8443), 0);
        System.out.println("Server dang chay tai http://localhost:8443 ...");

        // Tạo context xử lý HTTP request
        server.createContext("/", ServerMain::handleRequest);
        server.setExecutor(Executors.newFixedThreadPool(10)); // Thread pool xử lý song song

        // Load keystore chứa chứng chỉ và khóa bí mật
        char[] password = "Tanlaihoang2922004.".toCharArray(); // mật khẩu của keystore
        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream("src\\main\\java\\resources\\keystore.jks");
        ks.load(fis, password);

        // Tạo KeyManager từ keystore
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, password);

        // Tạo TrustManager từ keystore
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ks);

        // Tạo SSLContext để mã hóa HTTPS
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        // Cấu hình SSL cho server
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                try {
                    SSLContext context = getSSLContext();
                    SSLEngine engine = context.createSSLEngine();
                    params.setNeedClientAuth(false); // không yêu cầu client chứng thực
                    params.setCipherSuites(engine.getEnabledCipherSuites());
                    params.setProtocols(engine.getEnabledProtocols());
                    params.setSSLParameters(context.getDefaultSSLParameters());
                } catch (Exception ex) {
                    System.err.println("Lỗi cấu hình SSL: " + ex.getMessage());
                }
            }
        });

        server.start(); // Khởi động server
    }

    private static void handleRequest(HttpExchange exchange) throws IOException {
        // Chỉ xử lý POST
        if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
            exchange.sendResponseHeaders(405, -1); // 405: Method Not Allowed
            return;
        }

        // Đọc body từ request
        InputStream is = exchange.getRequestBody();
        String body = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        System.out.println("Nhan request: " + body);

        // Phân tích JSON
        Gson gson = new Gson();
        Type mapType = new TypeToken<Map<String, String>>() {
        }.getType();
        Map<String, String> json = gson.fromJson(body, mapType);

        // Lấy các trường dữ liệu
        String rawMessage = json.get("raw_message");
        String signedMessage = json.get("signed_message");
        String encryptedPublicKey = json.get("encrypted_public_key");
        String aesKeyBase64 = json.get("key");
        String ivBase64 = json.get("iv");

        String response = null;

        try {
            // Giải mã AES key và IV
            byte[] keyBytes = Base64.getDecoder().decode(aesKeyBase64);
            SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

            byte[] ivBytes = Base64.getDecoder().decode(ivBase64);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            // Lấy IP client
            String clientIp = exchange.getRemoteAddress().getAddress().getHostAddress();

            // Nếu có private key mã hóa (hiện tại không dùng), giải mã thử
            String encryptedPrivateKey = json.containsKey("encrypted_private_key") ? json.get("encrypted_private_key") : null;
            if (encryptedPrivateKey != null) {
                CryptoUtils.decryptAES(encryptedPrivateKey, aesKey, ivSpec);
            }

            // Giải mã public key
            String publicKeyPEM = CryptoUtils.decryptAES(encryptedPublicKey, aesKey, ivSpec);

            // Xác thực chữ ký số
            boolean verified = CryptoUtils.verifySignature(rawMessage, signedMessage, publicKeyPEM);

            if (verified) {
                System.out.println("Xác thực thành công.");

                // Trích xuất domain từ raw_message
                List<String> extractedDomains = DomainExtractor.extractDomains(rawMessage);

                if (!extractedDomains.isEmpty()) {
                    String firstDomain = extractedDomains.get(0);
                    DBHelper.saveKeyData(clientIp, firstDomain, publicKeyPEM, aesKeyBase64, ivBase64);

                    List<String> allSubdomains = new ArrayList<>();
                    for (String domain : extractedDomains) {
                        System.out.println("Scanning domain: " + domain);
                        List<String> subdomains = DomainScanner.scan(domain, 20); // scan giới hạn 20 subdomain
                        allSubdomains.addAll(subdomains);
                    }

                    response = gson.toJson(allSubdomains); // trả về danh sách subdomain
                    System.out.println("Scan complete. Tổng cộng " + allSubdomains.size() + " subdomains.");
                } else {
                    // Không có domain hợp lệ trong message
                    System.out.println("Không tìm thấy domain hợp lệ trong chuỗi raw_message.");
                    DBHelper.saveKeyData(clientIp, null, publicKeyPEM, aesKeyBase64, ivBase64);
                    response = "INVALID_DOMAIN_FORMAT";
                }
            } else {
                response = "VERIFICATION_FAILED"; // <-- THÊM DÒNG NÀY LÀ BẮT BUỘC
            }

        } catch (Exception ex) {
            response = "SERVER_ERROR: " + ex.getMessage();
        }

        // Trả response về cho client
        byte[] respBytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, respBytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(respBytes);
        }
    }
}
