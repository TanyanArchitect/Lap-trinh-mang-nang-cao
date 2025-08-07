package server;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class CryptoUtils {

    // Giải mã chuỗi đã mã hóa bằng AES CBC, trả về chuỗi gốc
    public static String decryptAES(String encryptedBase64, SecretKey key, IvParameterSpec ivSpec) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // Khởi tạo AES ở chế độ CBC
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);              // Gán key và IV
        byte[] decoded = Base64.getDecoder().decode(encryptedBase64); // Giải mã Base64 trước
        byte[] decrypted = cipher.doFinal(decoded);                   // Giải mã AES
        return new String(decrypted, StandardCharsets.UTF_8);         // Trả về chuỗi kết quả
    }

    // Xác thực chữ ký số dùng thuật toán SHA256withRSA
    public static boolean verifySignature(String rawMessage, String base64Signature, String publicKeyPEM) throws Exception {
        PublicKey publicKey = loadPublicKeyFromPEM(publicKeyPEM);  // Tạo đối tượng PublicKey từ PEM base64

        Signature signature = Signature.getInstance("SHA256withRSA"); // Sử dụng thuật toán ký RSA với SHA256
        signature.initVerify(publicKey);                              // Gán khóa để xác thực
        signature.update(rawMessage.getBytes(StandardCharsets.UTF_8)); // Cập nhật dữ liệu gốc để xác thực

        byte[] signedBytes = Base64.getDecoder().decode(base64Signature); // Giải mã chữ ký từ base64
        return signature.verify(signedBytes);                             // Trả về true nếu xác thực thành công
    }

    // Chuyển chuỗi PEM (base64) sang đối tượng PublicKey
    private static PublicKey loadPublicKeyFromPEM(String base64Key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(base64Key);           // Giải mã base64
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);        // Tạo định dạng khóa theo chuẩn X509
        KeyFactory kf = KeyFactory.getInstance("RSA");                    // Lấy factory cho RSA
        return kf.generatePublic(spec);                                   // Tạo đối tượng PublicKey từ spec
    }
}
