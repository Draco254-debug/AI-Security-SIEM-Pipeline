import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta

# Set random seed for reproducibility
np.random.seed(42)
random.seed(42)

def generate_security_dataset(num_rows=5000):
    logs = []
    
    # Base configuration data
    user_pool = [f"user_{i}" for i in range(1, 51)]
    ip_pool = [f"192.168.1.{i}" for i in range(1, 100)]
    methods = ["POST", "GET", "PUT", "DELETE"]
    endpoints = ["/login", "/dashboard", "/api/v1/data", "/settings", "/download/reports"]
    
    # Base timestamp (Start of a standard work week)
    base_time = datetime(2026, 10, 12, 8, 0, 0) 
    
    print(f"Generating {num_rows} raw system log entries...")

    # 1. GENERATE NORMAL TRAFFIC
    for _ in range(int(num_rows * 0.95)): # 95% of data will be completely normal
        user = random.choice(user_pool)
        ip = random.choice(ip_pool)
        
        # Normal work hours: randomly scatter between 08:00 and 18:00
        random_minutes = random.randint(0, 600)
        timestamp = base_time + timedelta(minutes=random_minutes) + timedelta(seconds=random.randint(0, 59))
        
        endpoint = random.choice(endpoints)
        method = "POST" if endpoint == "/login" else random.choice(methods)
        
        # FIX: Added the pool of standard HTTP status codes to choose from
        status_code = random.choice([200, 200, 200, 201, 304, 404]) 
        payload_bytes = random.randint(150, 5000) # Small standard payloads (bytes)
        
        logs.append([timestamp.strftime('%Y-%m-%d %H:%M:%S'), ip, user, method, endpoint, status_code, payload_bytes])

    # 2. INJECT ATTACK SCENARIO A: Brute Force Login Attack
    attacker_ip = "10.0.4.55"
    target_user = "admin_root"
    brute_time = base_time + timedelta(hours=2, minutes=15) # Happens at 10:15 AM
    
    for i in range(150): # 150 rapid attempts
        brute_time += timedelta(milliseconds=random.randint(100, 800)) # Milliseconds apart
        logs.append([brute_time.strftime('%Y-%m-%d %H:%M:%S'), attacker_ip, target_user, "POST", "/login", 401, 120])
    
    # The final attempt succeeds
    brute_time += timedelta(seconds=2)
    logs.append([brute_time.strftime('%Y-%m-%d %H:%M:%S'), attacker_ip, target_user, "POST", "/login", 200, 120])

    # 3. INJECT ATTACK SCENARIO B: Insomniac Data Exfiltration
    rogue_user = "user_12"
    rogue_ip = "192.168.1.12"
    exfil_time = base_time + timedelta(hours=19, minutes=30) # Pushes the clock to 3:30 AM the next day
    
    for _ in range(10): 
        exfil_time += timedelta(minutes=random.randint(1, 5))
        huge_payload = random.randint(5000000000, 10000000000) 
        logs.append([exfil_time.strftime('%Y-%m-%d %H:%M:%S'), rogue_ip, rogue_user, "GET", "/download/reports", 200, huge_payload])

    # Convert to Dataframe, shuffle it so attacks are realistically mixed in, and save
    df = pd.DataFrame(logs, columns=['timestamp', 'source_ip', 'username', 'http_method', 'endpoint', 'status_code', 'payload_bytes'])
    df = df.sample(frac=1).reset_index(drop=True) # Shuffling entries
    
    df.to_csv("raw_system_logs.csv", index=False)
    print("Dataset successfully generated and saved to 'raw_system_logs.csv'!")

if __name__ == "__main__":
    generate_security_dataset()
