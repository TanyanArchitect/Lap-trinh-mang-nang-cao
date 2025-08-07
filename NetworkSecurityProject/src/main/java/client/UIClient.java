package client;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

import java.util.HashMap;
import java.util.Map;
import java.net.URL;
import java.io.OutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import com.google.gson.Gson;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.net.ssl.*;

public class UIClient {

    private JFrame frame; // Cửa sổ chính
    private JTextField privateKeyField; // Ô nhập đường dẫn khóa riêng
    private JTextField publicKeyField;  // Ô nhập đường dẫn khóa công khai
    private JTextArea messageArea; // Ô nhập nội dung tin nhắn
    private JTextArea resultArea;  // Ô hiển thị phản hồi từ server

    public void showUI() {
        frame = new JFrame("Client UI - Gửi tin nhắn an toàn"); // Tạo cửa sổ
        frame.setSize(700, 600); // Kích thước cửa sổ
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); // Tắt chương trình khi đóng

        JPanel panel = new JPanel(new BorderLayout(10, 10)); // Panel chính, layout Border

        // Panel nhập liệu (trên cùng)
        JPanel inputPanel = new JPanel(new GridLayout(6, 1)); // Grid layout 6 hàng

        // Dòng nhập private key
        JPanel privateKeyPanel = new JPanel(new BorderLayout());
        privateKeyField = new JTextField(); // Trường nhập đường dẫn
        JButton browsePrivateBtn = new JButton("Browse..."); // Nút chọn file
        browsePrivateBtn.addActionListener(e -> browseFile(privateKeyField)); // Gắn sự kiện
        privateKeyPanel.add(privateKeyField, BorderLayout.CENTER);
        privateKeyPanel.add(browsePrivateBtn, BorderLayout.EAST);

        // Dòng nhập public key
        JPanel publicKeyPanel = new JPanel(new BorderLayout());
        publicKeyField = new JTextField();
        JButton browsePublicBtn = new JButton("Browse...");
        browsePublicBtn.addActionListener(e -> browseFile(publicKeyField));
        publicKeyPanel.add(publicKeyField, BorderLayout.CENTER);
        publicKeyPanel.add(browsePublicBtn, BorderLayout.EAST);

        messageArea = new JTextArea("Nhập message tại đây...", 3, 50); // Nhập tin nhắn

        // Thêm thành phần vào inputPanel
        inputPanel.add(new JLabel("Đường dẫn private key (.pem):"));
        inputPanel.add(privateKeyPanel);
        inputPanel.add(new JLabel("Đường dẫn public key (.pem):"));
        inputPanel.add(publicKeyPanel);
        inputPanel.add(new JLabel("Message:"));
        inputPanel.add(new JScrollPane(messageArea));

        // Nút gửi
        JButton sendBtn = new JButton("Gửi tới Server");
        sendBtn.addActionListener(this::handleSend); // Gắn hàm gửi

        // Vùng hiển thị kết quả (ở dưới)
        resultArea = new JTextArea(10, 50);
        resultArea.setEditable(false); // Không cho sửa
        resultArea.setLineWrap(true); // Tự xuống dòng

        // Gắn các panel vào frame
        panel.add(inputPanel, BorderLayout.NORTH); // Trên
        panel.add(sendBtn, BorderLayout.CENTER);   // Giữa
        panel.add(new JScrollPane(resultArea), BorderLayout.SOUTH); // Dưới

        frame.add(panel); // Gắn panel vào frame
        frame.setVisible(true); // Hiển thị giao diện
    }

    // Mở cửa sổ chọn file và gán đường dẫn vào ô nhập
    private void browseFile(JTextField targetField) {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(frame);
        if (result == JFileChooser.APPROVE_OPTION) {
            String path = fileChooser.getSelectedFile().getAbsolutePath();
            targetField.setText(path); // Gán vào text field
        }
    }

    // Hàm xử lý khi người dùng bấm "Gửi tới Server"
    private void handleSend(ActionEvent e) {
        try {
            String privateKeyPath = privateKeyField.getText().trim();
            String publicKeyPath = publicKeyField.getText().trim();
            String rawMessage = messageArea.getText().trim();

            // Kiểm tra nhập đủ đường dẫn
            if (privateKeyPath.isEmpty() || publicKeyPath.isEmpty()) {
                resultArea.setText("❌ INVALID: Bạn phải nhập đầy đủ đường dẫn private và public key.");
                return;
            }

            // Kiểm tra file tồn tại
            if (!Files.exists(Paths.get(privateKeyPath)) || !Files.exists(Paths.get(publicKeyPath))) {
                resultArea.setText("❌ INVALID: File khóa không tồn tại. Vui lòng kiểm tra lại đường dẫn.");
                return;
            }

            // Đọc khóa và ký message
            PrivateKey privateKey = CryptoUtils.loadPrivateKey(privateKeyPath);
            PublicKey publicKey = CryptoUtils.loadPublicKey(publicKeyPath);
            String signature = CryptoUtils.signMessage(rawMessage, privateKey); // Ký tin nhắn

            SecretKey aesKey = CryptoUtils.generateAESKey(); // Tạo khóa AES
            byte[] iv = CryptoUtils.generateIV(); // Sinh IV ngẫu nhiên

            String publicKeyPEM = CryptoUtils.encodePublicKey(publicKey); // Convert public key sang base64
            String encryptedPublicKey = CryptoUtils.encryptAES(publicKeyPEM, aesKey, iv); // Mã hóa bằng AES

            // Tạo JSON gửi lên server
            Map<String, String> jsonMap = new HashMap<>();
            jsonMap.put("raw_message", rawMessage);
            jsonMap.put("signed_message", signature);
            jsonMap.put("encrypted_public_key", encryptedPublicKey);
            jsonMap.put("key", CryptoUtils.encodeKey(aesKey));
            jsonMap.put("iv", CryptoUtils.encodeIV(iv));

            Gson gson = new Gson();
            String jsonPayload = gson.toJson(jsonMap); // Chuyển sang chuỗi JSON

            // Bỏ qua xác thực chứng chỉ SSL (CHỈ DÙNG KHI TEST LOCALHOST)
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
            };

            // Thiết lập context SSL tin tất cả chứng chỉ
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Bỏ qua kiểm tra hostname (dùng cho localhost)
            HostnameVerifier allHostsValid = (hostname, session) -> true;
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

            // Gửi POST tới server
            URL url = new URL("https://localhost:8443");
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setDoOutput(true); // Cho phép ghi dữ liệu
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");

            // Gửi JSON
            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonPayload.getBytes(StandardCharsets.UTF_8));
            }

            // Đọc phản hồi từ server
            InputStream is = conn.getInputStream();
            String response = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            resultArea.setText("📥 Server phản hồi:\n" + response);
        } catch (Exception ex) {
            resultArea.setText("❌ Lỗi khi gửi: " + ex.getMessage());
        }
    }
}
