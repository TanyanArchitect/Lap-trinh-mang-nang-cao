package server;

import java.sql.*;

public class DBHelper {

    // Thông tin kết nối đến MySQL database tên là secure_network
    private static final String URL = "jdbc:mysql://localhost:3306/secure_network?useSSL=false&serverTimezone=UTC";
    private static final String USER = "root"; // Tên người dùng cơ sở dữ liệu
    private static final String PASSWORD = "@Admin1234"; // Mật khẩu của người dùng cơ sở dữ liệu

    public static Connection connect() throws SQLException {
        // Tạo kết nối đến cơ sở dữ liệu và trả về đối tượng Connection
        return DriverManager.getConnection(URL, USER, PASSWORD);
    }

    public static void initialize() {
        // Phương thức dùng để thông báo khi kết nối thành công
        System.out.println("Da ket noi MySQL thanh cong.");
    }

    public static void saveKeyData(String clientIp, String result, String publicKey, String aesKey, String iv) {
        // Phương thức dùng để lưu thông tin khóa vào bảng key_storage

        String sql = "INSERT INTO key_storage (client_ip, result, public_key, aes_key, iv) VALUES (?, ?, ?, ?, ?)";
        // Câu lệnh SQL sử dụng PreparedStatement để tránh SQL injection

        try (
                Connection conn = connect(); // Tạo kết nối đến CSDL
                 PreparedStatement stmt = conn.prepareStatement(sql) // Chuẩn bị câu lệnh SQL
                ) {
            // Gán giá trị cho các dấu ? trong câu lệnh SQL
            stmt.setString(1, clientIp); // Gán địa chỉ IP của client
            stmt.setString(2, result);   // Gán domain nếu hợp lệ, hoặc null nếu không
            stmt.setString(3, publicKey); // Gán khóa RSA public
            stmt.setString(4, aesKey);    // Gán khóa AES đã mã hóa
            stmt.setString(5, iv);        // Gán giá trị IV dùng cho AES

            stmt.executeUpdate(); // Thực thi câu lệnh INSERT để lưu vào DB
            System.out.println("Du lieu da luu vao My SQL."); // Thông báo lưu thành công
        } catch (SQLException e) {
            // Bắt lỗi nếu có vấn đề khi lưu vào DB
            System.err.println("Loi khi luu vao DB: " + e.getMessage());
        }
    }

}
