package server;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DomainExtractor {

    // Phương thức để trích xuất các domain từ đoạn văn bản đầu vào
    public static List<String> extractDomains(String text) {
        List<String> domains = new ArrayList<>(); // Tạo danh sách để chứa các domain tìm được

        // Regex để khớp với domain, ví dụ: youtube.com, sub.domain.co.uk
        String domainRegex = "\\b((?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,})\\b";

        Pattern pattern = Pattern.compile(domainRegex); // Biên dịch biểu thức chính quy thành Pattern
        Matcher matcher = pattern.matcher(text); // Ánh xạ Pattern với văn bản đầu vào để tìm các khớp

        // Duyệt từng kết quả tìm được
        while (matcher.find()) {
            domains.add(matcher.group(1)); // Lấy domain khớp và thêm vào danh sách
        }

        return domains; // Trả về danh sách các domain đã tìm thấy
    }
}
