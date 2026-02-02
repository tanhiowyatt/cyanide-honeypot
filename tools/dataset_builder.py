#!/usr/bin/env python3
"""
SLM Dataset Generator (Synthetic)
Spins up a Docker container and executes random commands to capture authentic output.
"""
import subprocess
import json
import random
import time
import os

COMMANDS = [
    "ls -la", "pwd", "id", "whoami", "date", "uptime", "free -m", 
    "df -h", "ps aux", "netstat -tulnp", "cat /etc/issue", 
    "cat /proc/cpuinfo", "uname -a", "ip addr", "ifconfig"
]

OUTPUT_FILE = "dataset_shell_v1.jsonl"
DOCKER_IMAGE = "ubuntu:22.04"

def get_docker_output(cmd):
    try:
        # Run command in ephemeral container
        res = subprocess.run(
            ["docker", "run", "--rm", DOCKER_IMAGE, "bash", "-c", cmd],
            capture_output=True,
            text=True,
            timeout=5
        )
        return res.stdout, res.stderr, res.returncode
    except Exception as e:
        return "", str(e), -1

def main():
    print(f"[*] Generating dataset using {DOCKER_IMAGE}...")
    
    with open(OUTPUT_FILE, "a") as f:
        for i in range(100): # Generating 100 samples as demo
            cmd = random.choice(COMMANDS)
            
            # Add some variety/arguments if needed
            if random.random() > 0.8:
                cmd += " /tmp"
            
            stdout, stderr, rc = get_docker_output(cmd)
            
            output = stdout + stderr
            
            # ChatML Format or similar
            sample = {
                "instruction": "You are a Linux terminal. Provide the output for the following command.",
                "input": cmd,
                "output": output
            }
            
            f.write(json.dumps(sample) + "\n")
            
            if i % 10 == 0:
                print(f"Generated {i} samples...")
                
    print(f"[+] Dataset saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
