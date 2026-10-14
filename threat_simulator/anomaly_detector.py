import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import sqlite3
import os

def analyze_and_save_anomalies():
    # 1. LOAD DATASET
    # Since your database file is in your IntelliJ project, let's make sure your paths are right
    log_file = "raw_system_logs.csv"
    db_file = "siem_system.db"
    
    if not os.path.exists(log_file):
        print(f"[ERROR] Could not find {log_file}.")
        return
        
    print("[AI ENGINE] Loading system logs for behavioral analysis...")
    df = pd.read_csv(log_file)
    
    # 2. FEATURE ENGINEERING
    df['timestamp_parsed'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp_parsed'].dt.hour
    df['is_login'] = np.where(df['endpoint'] == '/login', 1, 0)
    df['is_failed'] = np.where(df['status_code'] == 401, 1, 0)
    
    features = ['hour', 'payload_bytes', 'is_login', 'is_failed']
    X = df[features]
    
    # 3. RUN MACHINE LEARNING ANOMALY DETECTION
    print("[AI ENGINE] Fitting Isolation Forest model to catch abnormal footprints...")
    model = IsolationForest(contamination=0.03, random_state=42)
    df['anomaly_score'] = model.fit_predict(X)
    
    # Isolate the data exfiltration events caught by AI (-1 means anomaly)
    # We filter out 401 errors because Java already handled them! We only want the stealthy threats.
    ai_anomalies = df[(df['anomaly_score'] == -1) & (df['status_code'] != 401)]
    
    print(f"[AI ENGINE] Found {len(ai_anomalies)} advanced stealth anomalies.")

    # 4. CONNECT TO SQLITE DATABASE AND SAVE RESULTS
    if os.path.exists(db_file):
        print(f"[AI ENGINE] Connecting to database '{db_file}'...")
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        alerts_written = 0
        for index, row in ai_anomalies.iterrows():
            # SQL Query to insert the AI-flagged alerts
            sql = """
            INSERT INTO security_alerts (source_ip, username, endpoint, risk_score, attack_type, details)
            VALUES (?, ?, ?, ?, ?, ?)
            """
            details_text = f"AI Behavioral Analysis flag. Volumetric anomaly detected at hour {row['hour']}. Size: {row['payload_bytes']} bytes."
            
            cursor.execute(sql, (
                row['source_ip'], 
                row['username'], 
                row['endpoint'], 
                5, # Risk Score: 5 (Critical)
                "AI Detected Malicious Exfiltration", 
                details_text
            ))
            alerts_written += 1
            
        conn.commit()
        conn.close()
        print(f"[AI ENGINE SUCCESS] Successfully pushed {alerts_written} machine learning alerts to database!")
    else:
        print(f"[WARN] Database file '{db_file}' not found in this folder. Copy it from your IntelliJ directory.")

if __name__ == "__main__":
    analyze_and_save_anomalies()
