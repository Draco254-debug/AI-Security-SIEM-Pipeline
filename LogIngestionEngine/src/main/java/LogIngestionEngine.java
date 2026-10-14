import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class LogIngestionEngine {

    private static final String LOG_FILE = "raw_system_logs.csv";
    private static final AtomicInteger totalLogsProcessed = new AtomicInteger(0);
    private static final AtomicInteger databaseAlertsRecorded = new AtomicInteger(0);

    public static void main(String[] args) {
        long startTime = System.currentTimeMillis();
        System.out.println("[SIEM ENGINE INITIATED] Allocating thread pool for ingestion...");

        int availableCores = Runtime.getRuntime().availableProcessors();
        System.out.println("[SYSTEM INFO] Available CPU Cores: " + availableCores);
        ExecutorService threadPool = Executors.newFixedThreadPool(availableCores);

        try (BufferedReader br = new BufferedReader(new FileReader(LOG_FILE))) {
            String line;
            br.readLine(); // Skip CSV header row

            while ((line = br.readLine()) != null) {
                final String lineToProcess = line;

                threadPool.submit(() -> {
                    LogEntry entry = LogParser.parseLine(lineToProcess);
                    if (entry != null) {
                        totalLogsProcessed.incrementAndGet();

                        // 1. CHANNELS BRUTE FORCE SCENARIOS TO DATABASE (Status Code 401)
                        if (entry.statusCode == 401) {
                            databaseAlertsRecorded.incrementAndGet();
                            DatabaseManager.insertSecurityAlert(
                                    entry.sourceIp,
                                    entry.username,
                                    entry.endpoint,
                                    3, // Risk Score: Medium Warning
                                    "Brute Force Attempt",
                                    "Rapid authentication failure detected on login panel interface."
                            );
                        }

                        // 2. CHANNELS MASSIVE DATA SPILLS TO DATABASE (Payloads > 1 GB)
                        if (entry.payloadBytes > 1000000000) {
                            databaseAlertsRecorded.incrementAndGet();
                            DatabaseManager.insertSecurityAlert(
                                    entry.sourceIp,
                                    entry.username,
                                    entry.endpoint,
                                    5, // Risk Score: Critical Threat
                                    "Data Exfiltration",
                                    "Abnormal volumetric output size: " + (entry.payloadBytes / 1024 / 1024) + " MB exported."
                            );
                        }
                    }
                });
            }

        } catch (IOException e) {
            System.err.println("[CRITICAL ERROR] Failed to read log file: " + e.getMessage());
        }

        // Properly wrap up running tasks
        threadPool.shutdown();
        try {
            if (!threadPool.awaitTermination(60, TimeUnit.SECONDS)) {
                threadPool.shutdownNow();
            }
        } catch (InterruptedException e) {
            threadPool.shutdownNow();
        }

        long endTime = System.currentTimeMillis();
        System.out.println("\n==================================================");
        System.out.println("[INGESTION COMPLETE]");
        System.out.println("Total Successfully Parsed Logs: " + totalLogsProcessed.get());
        System.out.println("Security Threat Incidents Saved to DB: " + databaseAlertsRecorded.get());
        System.out.println("Execution Pipeline Speed: " + (endTime - startTime) + " ms");
        System.out.println("==================================================");
    }
}
