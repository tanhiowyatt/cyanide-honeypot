# Developer Guide

Simple instructions to run the project for verification and development.

## 1. Quick Start (Run Honeypot)

Start the main backend server (Cyanide):

```bash
./bin/cyanide start
```
*Logs are in `var/log/cyanide.out`.*

To stop it:
```bash
./bin/cyanide stop
```

## 2. Run SSH Proxy (Optional)

If you want to use the Man-in-the-Middle SSH proxy (port 2220 -> 2222):

```bash
# Ensure backend is running first!
./bin/cyanide start

# Start Proxy
python3 src/proxy/ssh_proxy.py
```
*Proxy listens on port **2220**.*

## 3. Run Tests

Run automated integration tests:
```bash
pytest
```

Run manual proxy verification:
```bash
python3 tests/manual_proxy_test.py
```

## 4. Reset Filesystem

To revert the fake filesystem to its default state or update it from source:

```bash
./bin/cyanide-createfs src/commands
```

## Directory Reference
- `src/core/`: Backend logic.
- `src/commands/`: Fake shell commands.
- `src/proxy/`: SSH interception proxy.
