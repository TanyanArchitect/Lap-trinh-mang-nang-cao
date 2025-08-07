package client;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import java.util.Base64;

public class CryptoUtils {

    // Tải private key từ file PEM (định dạng PKCS#8)
    public static PrivateKey loadPrivateKey(String filename) throws Exception {
        String key = new String(Files.readAllBytes(Paths.get(filename))) // Đọc toàn bộ file thành chuỗi
                .replace("-----BEGIN PRIVATE KEY-----", "") // Bỏ phần header PEM
                .replace("-----END PRIVATE KEY-----", "") // Bỏ phần footer PEM
                .replaceAll("\\s", "");                                   // Bỏ khoảng trắng, xuống dòng

        byte[] keyBytes = Base64.getDecoder().decode(key);               // Giải mã base64
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);   // Tạo key spec PKCS#8
        KeyFactory kf = KeyFactory.getInstance("RSA");                   // Sử dụng thuật toán RSA
        return kf.generatePrivate(spec);                                 // Trả về đối tượng PrivateKey
    }

    // Tải public key từ file PEM (định dạng X.509)
    public static PublicKey loadPublicKey(String filename) throws Exception {
        String key = new String(Files.readAllBytes(Paths.get(filename)))
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes); // X.509 dùng cho public key
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    // Chuyển public key sang chuỗi base64 (dùng để gửi đi)
    public static String encodePublicKey(PublicKey publicKey) {
        byte[] encoded = publicKey.getEncoded();                       // Lấy byte mảng
        return Base64.getEncoder().encodeToString(encoded);           // Mã hóa base64
    }

    // Ký tin nhắn bằng SHA256withRSA
    public static String signMessage(String rawMessage, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");   // Tạo đối tượng Signature
        signature.initSign(privateKey);                                 // Khởi tạo với private key
        signature.update(rawMessage.getBytes(StandardCharsets.UTF_8));  // Cập nhật dữ liệu cần ký
        byte[] signedBytes = signature.sign();                          // Ký và lấy kết quả
        return Base64.getEncoder().encodeToString(signedBytes);         // Mã hóa base64 để gửi
    }

    // Sinh khóa AES 256-bit
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES"); // Lấy generator AES
        keyGen.init(256); // Đặt độ dài khóa là 256-bit (cần JCE Unlimited nếu máy không hỗ trợ thì đổi thành 128)
        return keyGen.generateKey(); // Tạo khóa
    }

    // Sinh IV ngẫu nhiên (16 byte cho AES CBC)
    public static byte[] generateIV() {
        byte[] iv = new byte[16]; // 16 byte = 128-bit
        new SecureRandom().nextBytes(iv); // Sinh ngẫu nhiên
        return iv;
    }

    // Mã hóa dữ liệu bằng AES (CBC mode, có padding)
    public static String encryptAES(String data, SecretKey key, byte[] ivBytes) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // AES CBC với padding
        IvParameterSpec iv = new IvParameterSpec(ivBytes);          // IV truyền vào
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);                  // Chế độ mã hóa
        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)); // Mã hóa dữ liệu
        return Base64.getEncoder().encodeToString(encrypted);       // Trả về dạng base64
    }

    // Mã hóa (encode) khóa AES thành base64 để dễ gửi/nhận qua JSON
    public static String encodeKey(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // Mã hóa IV thành base64
    public static String encodeIV(byte[] iv) {
        return Base64.getEncoder().encodeToString(iv);
    }
}
