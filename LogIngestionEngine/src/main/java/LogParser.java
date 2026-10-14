import java.util.regex.Pattern;

public class LogParser {
    // A strict Regex pattern to validate and parse our comma-separated log entries safely
    // Protects against log injection tampering
    private static final Pattern CSV_PATTERN = Pattern.compile(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");

    public static LogEntry parseLine(String line) {
        if (line == null || line.trim().isEmpty() || line.startsWith("timestamp")) {
            return null; // Skip empty lines and the CSV header row
        }

        // Split the line by commas, safely ignoring commas enclosed inside quotation marks
        String[] tokens = CSV_PATTERN.split(line);

        if (tokens.length < 7) {
            return null; // Malformed log line, skip it to prevent crashes
        }

        try {
            String timestamp = tokens[0].replace("\"", "");
            String sourceIp = tokens[1].replace("\"", "");
            String username = tokens[2].replace("\"", "");
            String httpMethod = tokens[3].replace("\"", "");
            String endpoint = tokens[4].replace("\"", "");
            int statusCode = Integer.parseInt(tokens[5].trim());
            long payloadBytes = Long.parseLong(tokens[6].trim());

            return new LogEntry(timestamp, sourceIp, username, httpMethod, endpoint, statusCode, payloadBytes);
        } catch (Exception e) {
            // Log parsing failure (e.g., character data inside payloadBytes)
            System.err.println("Skipping corrupted log entry row: " + e.getMessage());
            return null;
        }
    }
}

// A structured Data Object (POJO) to hold our clean log metrics securely in memory
class LogEntry {
    String timestamp;
    String sourceIp;
    String username;
    String httpMethod;
    String endpoint;
    int statusCode;
    long payloadBytes;

    public LogEntry(String timestamp, String sourceIp, String username, String httpMethod,
                    String endpoint, int statusCode, long payloadBytes) {
        this.timestamp = timestamp;
        this.sourceIp = sourceIp;
        this.username = username;
        this.httpMethod = httpMethod;
        this.endpoint = endpoint;
        this.statusCode = statusCode;
        this.payloadBytes = payloadBytes;
    }

    @Override
    public String toString() {
        return String.format("[%s] IP: %s | User: %s | %s %s | Status: %d | Size: %d bytes",
                timestamp, sourceIp, username, httpMethod, endpoint, statusCode, payloadBytes);
    }
}
