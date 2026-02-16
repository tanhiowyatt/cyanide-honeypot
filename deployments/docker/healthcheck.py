import requests
import sys

import os

METRICS_PORT = os.getenv("METRICS_PORT", "9090")
HEALTH_URL = f"http://127.0.0.1:{METRICS_PORT}/health"

def check_health():
    try:
        response = requests.get(HEALTH_URL, timeout=5)
        
        if response.status_code != 200:
            print(f"Health check failed: HTTP {response.status_code}")
            sys.exit(1)
            
        data = response.json()
        if data.get("status") != "healthy":
            print(f"Health check failed: Status {data.get('status')}")
            sys.exit(1)
            
        print(f"Healthy: SSH={data.get('ssh')}, Telnet={data.get('telnet')}")
        sys.exit(0)
        
    except requests.ConnectionError:
        print("Health check failed: Could not connect to Cyanide metrics server")
        sys.exit(1)
    except requests.Timeout:
        print("Health check failed: Request timed out")
        sys.exit(1)
    except requests.RequestException as e:
        print(f"Health check failed: HTTP Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Health check failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    check_health()
