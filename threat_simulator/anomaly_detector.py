import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import sqlite3
import os

def advanced_analytics():
    log_file = "raw_system_logs.csv"
    db_file = "siem_system.db"
    
    if not os.path.exists(log_file): return
    df = pd.read_csv(log_file)
    
    # Sort by timestamp to properly calculate time-based rolling sequences
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values(by='timestamp').reset_index(drop=True)
    
    print("[AI ENGINE] Calculating behavioral velocity metrics...")
    
    # FEATURE 1: Request Count per IP in a rolling window
    # Tracks high-frequency actions (Scrapers & Scanners)
    df['ip_count_5m'] = df.groupby('source_ip')['timestamp'].diff().dt.total_seconds().fillna(999)
    # Inverse the time delta so that high speed equals a high value
    df['request_velocity'] = 1.0 / (df['ip_count_5m'] + 0.1)

    # FEATURE 2: Count unique endpoints hit by the same IP
    # High diversity + high 404 errors = Port Scanner
    df['unique_endpoints_hit'] = df.groupby('source_ip')['endpoint'].transform('nunique')
    df['is_404'] = np.where(df['status_code'] == 404, 1, 0)
    
    # 3. TRAIN UPGRADED MULTI-VECTOR MODEL
    features = ['request_velocity', 'unique_endpoints_hit', 'is_404', 'payload_bytes']
    X = df[features]
    
    print("[AI ENGINE] Analysing multi-vector attack profiles...")
    model = IsolationForest(contamination=0.08, random_state=42) # Slightly higher contamination for more vectors
    df['anomaly_score'] = model.fit_predict(X)
    
    ai_anomalies = df[df['anomaly_score'] == -1]
    
    # 4. ROUTE CLASSIFICATION LOGIC
    if os.path.exists(db_file):
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        alerts_written = 0
        
        for idx, row in ai_anomalies.iterrows():
            # Determine specific attack type classification
            if row['unique_endpoints_hit'] > 15 and row['is_404'] == 1:
                attack_type = "Reconnaissance Port Scan"
                risk = 4
                details = f"IP scanning hidden infrastructure vectors. Unique endpoints explored: {row['unique_endpoints_hit']}."
            elif row['request_velocity'] > 5 and row['payload_bytes'] < 5000:
                attack_type = "Automated Web Scraping"
                risk = 3
                details = f"High-velocity content harvesting framework detected. Request velocity threshold breached."
            else:
                continue # Skip standard variations for clarity
                
            sql = "INSERT INTO security_alerts (source_ip, username, endpoint, risk_score, attack_type, details) VALUES (?, ?, ?, ?, ?, ?)"
            cursor.execute(sql, (row['source_ip'], row['username'], row['endpoint'], risk, attack_type, details))
            alerts_written += 1
            
        conn.commit()
        conn.close()
        print(f"[AI ENGINE SUCCESS] Successfully pushed {alerts_written} categorized security alerts to database!")

if __name__ == "__main__":
    advanced_analytics()
