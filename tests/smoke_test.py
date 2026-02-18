import socket
import sys
import time


def check_port(host, port, timeout=5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False


async def check_ssh_functional(host, port):
    """Try to login and execute a simple command."""
    try:
        import asyncssh

        async with asyncssh.connect(
            host, port=port, username="root", password="admin", known_hosts=None
        ) as conn:
            result = await conn.run("whoami", check=True)
            if "root" in result.stdout:
                return True, "Login and command execution OK"
            return False, f"Unexpected output: {result.stdout}"
    except Exception as e:
        return False, str(e)


def smoke_test():
    host = "127.0.0.1"
    ports = {"SSH": 2222, "Telnet": 2223, "Metrics": 9090}

    print("[*] Starting Smoke Test...")
    all_passed = True

    # Wait for service startup
    for i in range(10):
        if check_port(host, 9090):
            break
        print(f"Waiting for service... {i+1}/10")
        time.sleep(2)

    for name, port in ports.items():
        if check_port(host, port):
            print(f"[+] {name} (Port {port}): UP")
        else:
            print(f"[-] {name} (Port {port}): DOWN")
            all_passed = False

    # Functional SSH Test
    import asyncio

    try:
        ok, msg = asyncio.run(check_ssh_functional(host, 2222))
        if ok:
            print(f"[+] SSH Functional: {msg}")
        else:
            print(f"[-] SSH Functional FAILED: {msg}")
            all_passed = False
    except Exception as e:
        print(f"[-] SSH Functional Error: {e}")
        all_passed = False

    # Check /health endpoint

    try:
        data = None
        try:
            import requests

            response = requests.get(f"http://{host}:9090/health", timeout=5)
            if response.status_code == 200:
                data = response.json()
        except ImportError:
            import json
            import urllib.request

            with urllib.request.urlopen(f"http://{host}:9090/health", timeout=5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())

        if data:
            if data.get("status") == "healthy":
                print("[+] Health Endpoint: OK")
            else:
                print(f"[-] Health Endpoint: UNHEALTHY ({data})")
                all_passed = False
        else:
            print("[-] Health Endpoint: FAILED (No data)")
            all_passed = False
    except Exception as e:
        print(f"[-] Health Endpoint Error: {e}")
        all_passed = False

    if all_passed:
        print("[*] Smoke Test PASSED")
        sys.exit(0)
    else:
        print("[!] Smoke Test FAILED")
        sys.exit(1)


if __name__ == "__main__":
    smoke_test()
