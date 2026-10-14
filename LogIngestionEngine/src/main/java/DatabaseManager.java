import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class DatabaseManager {
    // Points directly to the local SQLite database file inside your project root directory
    private static final String DB_URL = "jdbc:sqlite:siem_system.db";

    // Synchronized method guarantees safe multi-threaded writes without database file lock crashes
    public static synchronized void insertSecurityAlert(String sourceIp, String username,
                                                        String endpoint, int riskScore,
                                                        String attackType, String details) {

        String sql = "INSERT INTO security_alerts (source_ip, username, endpoint, risk_score, attack_type, details) VALUES (?, ?, ?, ?, ?, ?)";

        try (Connection conn = DriverManager.getConnection(DB_URL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // Map our variables to the safe SQL query placeholders to completely block SQL Injection attacks
            pstmt.setString(1, sourceIp);
            pstmt.setString(2, username);
            pstmt.setString(3, endpoint);
            pstmt.setInt(4, riskScore);
            pstmt.setString(5, attackType);
            pstmt.setString(6, details);

            pstmt.executeUpdate();

        } catch (SQLException e) {
            System.err.println("[DATABASE ERROR] Failed to record security incident: " + e.getMessage());
        }
    }
}
