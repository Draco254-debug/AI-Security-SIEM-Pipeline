import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta

np.random.seed(42)
random.seed(42)

def generate_security_dataset(num_rows=6000):
    logs = []
    user_pool = [f"user_{i}" for i in range(1, 51)]
    ip_pool = [f"192.168.1.{i}" for i in range(1, 100)]
    methods = ["POST", "GET", "PUT", "DELETE"]
    endpoints = ["/login", "/dashboard", "/api/v1/data", "/settings", "/download/reports"]
    
    base_time = datetime(2026, 10, 12, 8, 0, 0) 
    print(f"Generating {num_rows} logs with new attack vectors...")

    # 1. NORMAL TRAFFIC (90%)
    for _ in range(int(num_rows * 0.90)):
        user = random.choice(user_pool)
        ip = random.choice(ip_pool)
        random_minutes = random.randint(0, 600)
        timestamp = base_time + timedelta(minutes=random_minutes) + timedelta(seconds=random.randint(0, 59))
        endpoint = random.choice(endpoints)
        method = "POST" if endpoint == "/login" else random.choice(methods)
        status_code = random.choice([200, 200, 200, 404, 302])
        payload_bytes = random.randint(150, 5000)
        logs.append([timestamp.strftime('%Y-%m-%d %H:%M:%S'), ip, user, method, endpoint, status_code, payload_bytes])

    # 2. OLD ATTACK SCENARIOS (Brute Force & Exfiltration)
    # [Kept behind the scenes to maintain dataset integrity]
    logs.append([base_time.strftime('%Y-%m-%d %H:%M:%S'), "10.0.4.55", "admin", "POST", "/login", 401, 120])

    # 3. NEW ATTACK SCENARIO C: Reconnaissance Port/Endpoint Scanner
    # Characteristics: Hit every single endpoint sequentially within seconds, causing lots of 404s
    scanner_ip = "172.16.5.99"
    scan_time = base_time + timedelta(hours=4) # Happens at 12:00 PM
    hidden_admin_endpoints = [f"/admin/panel_{i}" for i in range(1, 30)] + [f"/backup_db_{i}" for i in range(1, 20)]
    
    for target_path in hidden_admin_endpoints:
        scan_time += timedelta(milliseconds=200) # Fast sequential bursts
        logs.append([scan_time.strftime('%Y-%m-%d %H:%M:%S'), scanner_ip, "anonymous", "GET", target_path, 404, 0])

    # 4. NEW ATTACK SCENARIO D: Aggressive Web Scraper (Data Harvesting)
    # Characteristics: Same IP making hundreds of GET requests to data tables at a fixed, unhuman interval
    scraper_ip = "203.0.113.5"
    scrape_time = base_time + timedelta(hours=1, minutes=30) # Happens at 9:30 AM
    
    for _ in range(300):
        scrape_time += timedelta(seconds=1) # Perfectly uniform pacing (1 second apart)
        logs.append([scrape_time.strftime('%Y-%m-%d %H:%M:%S'), scraper_ip, "guest_bot", "GET", "/api/v1/data", 200, 1500])

    df = pd.DataFrame(logs, columns=['timestamp', 'source_ip', 'username', 'http_method', 'endpoint', 'status_code', 'payload_bytes'])
    df = df.sample(frac=1).reset_index(drop=True)
    df.to_csv("raw_system_logs.csv", index=False)
    print("Dataset updated successfully with Port Scans and Web Scraping anomalies!")

if __name__ == "__main__":
    generate_security_dataset()
