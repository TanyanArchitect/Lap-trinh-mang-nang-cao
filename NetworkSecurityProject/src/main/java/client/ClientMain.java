package client;

public class ClientMain {

    public static void main(String[] args) {
        // Gọi luồng giao diện đồ họa (GUI) của Java để tạo giao diện người dùng
        javax.swing.SwingUtilities.invokeLater(() -> {
            // Tạo đối tượng UIClient và hiển thị giao diện
            new UIClient().showUI();
        });
    }
}
