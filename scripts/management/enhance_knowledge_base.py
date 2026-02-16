
import json
from pathlib import Path
import sys
import os

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.getcwd(), 'src')))

from cyanide.ml.classifier import KnowledgeBase

KB_DATA_DIR = Path("data/ml_training/kb_ready")
MAPPINGS_FILE = KB_DATA_DIR / "manual_mappings.jsonl"
KB_MODEL_PATH = Path("ai_models/cyanideML/knowledge_base.pkl")

MANUAL_MAPPINGS = [
    # -- Reconnaissance --
    {"cmd": "uname -a", "tech": "T1082", "name": "System Information Discovery"},
    {"cmd": "cat /proc/version", "tech": "T1082", "name": "System Information Discovery"},
    {"cmd": "lsb_release -a", "tech": "T1082", "name": "System Information Discovery"},
    {"cmd": "hostnamectl", "tech": "T1082", "name": "System Information Discovery"},
    {"cmd": "cat /etc/os-release", "tech": "T1082", "name": "System Information Discovery"},
    {"cmd": "cat /etc/issue", "tech": "T1082", "name": "System Information Discovery"},
    
    {"cmd": "cat /etc/passwd", "tech": "T1087.001", "name": "Account Discovery: Local Account"},
    {"cmd": "getent passwd", "tech": "T1087.001", "name": "Account Discovery: Local Account"},
    {"cmd": "id", "tech": "T1033", "name": "System Owner/User Discovery"},
    {"cmd": "whoami", "tech": "T1033", "name": "System Owner/User Discovery"},
    {"cmd": "w", "tech": "T1033", "name": "System Owner/User Discovery"},
    {"cmd": "who", "tech": "T1033", "name": "System Owner/User Discovery"},
    {"cmd": "last", "tech": "T1033", "name": "System Owner/User Discovery"},

    # -- Privilege Escalation --
    {"cmd": "sudo su", "tech": "T1548.003", "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"},
    {"cmd": "sudo -l", "tech": "T1548.003", "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"},
    {"cmd": "sudo -i", "tech": "T1548.003", "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"},
    {"cmd": "sudo /bin/bash", "tech": "T1548.003", "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"},
    {"cmd": "sudo /bin/sh", "tech": "T1548.003", "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"},

    # -- Credential Access --
    {"cmd": "cat /etc/shadow", "tech": "T1003.008", "name": "OS Credential Dumping: /etc/passwd and /etc/shadow"},
    {"cmd": "cat /root/.ssh/id_rsa", "tech": "T1552.004", "name": "Unsecured Credentials: Private Keys"},
    {"cmd": "cat ~/.ssh/id_rsa", "tech": "T1552.004", "name": "Unsecured Credentials: Private Keys"},
    {"cmd": "grep password /var/log/", "tech": "T1552.001", "name": "Unsecured Credentials: Credentials In Files"},
    {"cmd": "history | grep password", "tech": "T1552.003", "name": "Unsecured Credentials: Credentials In Bash History"},

    # -- Persistence --
    {"cmd": "echo >> .bashrc", "tech": "T1546.004", "name": "Event Triggered Execution: Unix Shell Configuration Modification"},
    {"cmd": "echo >> .bash_profile", "tech": "T1546.004", "name": "Event Triggered Execution: Unix Shell Configuration Modification"},
    {"cmd": "echo >> .zshrc", "tech": "T1546.004", "name": "Event Triggered Execution: Unix Shell Configuration Modification"},
    {"cmd": "echo >> /etc/profile", "tech": "T1546.004", "name": "Event Triggered Execution: Unix Shell Configuration Modification"},
    
    {"cmd": "crontab -e", "tech": "T1053.003", "name": "Scheduled Task/Job: Cron"},
    {"cmd": "crontab -l", "tech": "T1053.003", "name": "Scheduled Task/Job: Cron"},
    {"cmd": "echo >> /etc/crontab", "tech": "T1053.003", "name": "Scheduled Task/Job: Cron"},

    # -- Command and Control / Tools --
    {"cmd": "wget", "tech": "T1105", "name": "Ingress Tool Transfer"},
    {"cmd": "curl", "tech": "T1105", "name": "Ingress Tool Transfer"},
    {"cmd": "nc -e", "tech": "T1059", "name": "Command and Scripting Interpreter"},
    {"cmd": "ncat -e", "tech": "T1059", "name": "Command and Scripting Interpreter"},
    {"cmd": "bash -i", "tech": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell"},
]

def generate_manual_mappings():
    print(f"[*] Generating manual mappings to {MAPPINGS_FILE}...")
    KB_DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    with open(MAPPINGS_FILE, 'w') as f:
        for m in MANUAL_MAPPINGS:
            entry = {
                "input": m["cmd"],
                "instruction": "Map command to MITRE ATT&CK technique",
                "output": f"{m['tech']} - {m['name']}",
                "metadata": {
                    "source": "manual_mapping",
                    "confidence": 1.0,
                    "verified": True
                }
            }
            f.write(json.dumps(entry) + "\n")
            
    print(f"[+] Written {len(MANUAL_MAPPINGS)} mappings.")

def rebuild_kb():
    print("[*] Rebuilding Knowledge Base index...")
    kb = KnowledgeBase()
    
    # Load all data including new manual mappings
    kb.load_data(KB_DATA_DIR)
    
    # Check if manual mappings loaded
    manual_count = sum(1 for me in kb.command_metadata if me.get('metadata', {}).get('source') == 'manual_mapping')
    print(f"[*] Loaded {manual_count} manual mappings.")
    
    # Build
    kb.build_index()
    
    # Save
    kb.save(KB_MODEL_PATH)

if __name__ == "__main__":
    generate_manual_mappings()
    rebuild_kb()
