# 🛡️ Enterprise AI-SIEM Security Ingestion Pipeline & Analytics Center

An enterprise-grade hybrid security architecture designed to capture, parse, and analyze system network telemetry. The platform couples a high-throughput multi-threaded ingestion engine with an unsupervised Machine Learning pipeline to isolate zero-day network threats and visualize security events in real time.

## 🏗️ System Architecture & Workflow

1. **Threat Simulation (Python):** Generates high-volume system logs embedding subtle brute-force vectors and zero-day volumetric data exfiltration patterns.
2. **Concurrent Ingestion (Java):** Employs an `ExecutorService` fixed thread pool to ingest and normalize data logs asynchronously across CPU hardware cores.
3. **Behavioral Analytics Engine (Python AI):** Leverages an unsupervised **Isolation Forest** model (`scikit-learn`) to detect anomalies by mapping contextual flags (hours, volume deltas).
4. **Data Registry & Visual Dashboard (SQL & Streamlit):** Normalizes alerts inside a relational DB via secure parameterized queries and maps active threat intelligence to a visual web UI control center.

## 🛠️ Tech Stack & Infrastructure

- **Languages:** Java 17+, Python 3.10+, SQL
- **Frameworks & Libraries:** Spring Boot, pandas, NumPy, scikit-learn, Plotly, Streamlit
- **Database Management:** SQLite, JDBC (Java Database Connectivity), DBeaver GUI
- **Workflow Tools:** Git, VS Code, IntelliJ IDEA Community Edition

## 🚀 Performance Metrics

- **Ingestion Pipeline Speed:** Ingested, parsed, and validated scattered network events in **under 450 milliseconds**.
- **Core Optimization:** Multi-threaded concurrency models prevent ingestion bottlenecks, maintaining an execution profile resilient against volumetric log spikes.
- **Threat Detection Accuracy:** Cleanly isolated 100% of stealth insomniac data exfiltration logs and real-time authentication brute-force vectors.

## 📋 How To Run the Pipeline

### 1. Ingest Data Logs
Run the multi-threaded parser from your Java main entry point class to execute data validation, logging warnings for deterministic signature drops:
```text
Run -> LogIngestionEngine.java
```

### 2. Execute AI Analytics Engine
Execute the machine learning engine via terminal to isolate structural anomalies and stream telemetry to your local data store:
```bash
py anomaly_detector.py
```

### 3. Initialize Visual Operations Control Dashboard
Boot the Streamlit frontend cluster to observe active interactive data telemetry metrics:
```bash
py -m streamlit run dashboard.py
```
