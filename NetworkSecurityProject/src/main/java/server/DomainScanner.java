package server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class DomainScanner {

    // Quét tối đa maxCount subdomains từ wordlist
    public static List<String> scan(String rootDomain, int maxCount) {
        List<String> found = new ArrayList<>(); // Danh sách lưu subdomain tìm thấy

        try {
            // Tải wordlist từ GitHub chứa danh sách subdomain phổ biến
            URL wordlistURL = new URL("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt");

            // Đọc nội dung wordlist qua stream
            BufferedReader reader = new BufferedReader(new InputStreamReader(wordlistURL.openStream()));

            String line;
            int count = 0;

            // Đọc từng dòng trong wordlist, tối đa maxCount dòng
            while ((line = reader.readLine()) != null && count < maxCount) {
                String subdomain = line.trim() + "." + rootDomain; // Ghép subdomain với domain chính

                // Kiểm tra xem subdomain có phản hồi HTTP hay không
                if (isDomainAlive("http://" + subdomain)) {
                    System.out.println("Tim thay: " + subdomain); // Nếu tồn tại, in ra và thêm vào danh sách
                    found.add(subdomain);
                } else {
                    System.out.println("Khong ton tai: " + subdomain); // Nếu không tồn tại, in thông báo
                }
                count++; // Tăng bộ đếm để giới hạn số lượng kiểm tra
            }

        } catch (IOException e) {
            // Nếu có lỗi khi tải wordlist hoặc kết nối mạng, in lỗi
            System.err.println("Lỗi khi tải wordlist: " + e.getMessage());
        }

        return found; // Trả về danh sách các subdomain tồn tại
    }

    // Hàm kiểm tra domain có "sống" hay không bằng cách gửi HTTP GET
    public static boolean isDomainAlive(String urlStr) {
        try {
            URL url = new URL(urlStr); // Tạo URL từ chuỗi
            HttpURLConnection conn = (HttpURLConnection) url.openConnection(); // Mở kết nối HTTP

            conn.setConnectTimeout(2000); // Thiết lập timeout kết nối là 2 giây
            conn.setReadTimeout(2000); // Thiết lập timeout đọc dữ liệu là 2 giây
            conn.setRequestMethod("GET"); // Gửi yêu cầu GET

            int code = conn.getResponseCode(); // Lấy mã phản hồi HTTP

            return code == 200 || code == 301 || code == 302;

        } catch (IOException e) {
            // Nếu không kết nối được, trả về false
            return false;
        }
    }
}
