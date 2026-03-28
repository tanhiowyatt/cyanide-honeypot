# 🛠️ Troubleshooting Guide

This guide covers common issues encountered while deploying or operating Cyanide.

## 🚫 Common Error Messages

### 1. "libvirt-python is required for libvirt pool mode"
**Cause**: `backend_mode` is set to `pool` with `mode: libvirt`, but the library is missing.
**Fix**: Run `pip install .[libvirt]` or ensure your Dockerfile includes `libvirt-dev` headers and the python binding.

### 2. "name 'libvirt' is not defined"
**Cause**: The `libvirt` library failed to import, often due to missing system dependencies (`libvirt-dev`).
**Fix**: 
- Ubuntu: `sudo apt-get install libvirt-dev`
- Mac: `brew install libvirt`

### 3. "AttributeError: 'NoneType' object has no attribute 'X'" (in VMPool)
**Cause**: The backend was not initialized correctly, likely because `pool.enabled` is `false` in `app.yaml` but a session attempted to request a VM.
**Fix**: Ensure `pool.enabled: true` and `backend_mode: pool` are set consistently.

---

## 🕵️ Debugging Techniques

### 1. Increase Log Verbosity
Change the logging level in your environment to see detailed flow transitions:
```bash
export CYANIDE_LOGGING_LEVEL=DEBUG
python3 -m cyanide.main
```

### 2. Validation Checks
Run the built-in validation suite to ensure your OS profiles and static manifests are healthy:
```bash
./.venv/bin/pytest tests/unit/test_config.py
./.venv/bin/pytest tests/unit/test_vfs_resiliency.py
```

### 3. Connection Timeouts
If SSH connections drop immediately:
- Check `CYANIDE_SSH_PORT` (default 2222) isn't blocked by a firewall.
- Verify the `OS_PROFILE` folder actually exists in `configs/profiles/`.
- Look for `Permission Denied` errors in `cyanide-server.json` which might indicate the process lacks rights to bind to the port (ports < 1024 require root).

## 🌍 Networking Issues

### Attacker cannot see PTY
If an attacker connects but sees no prompt:
- Ensure `backend_mode` is set correctly. If using `proxy`, ensure the target host is reachable from the honeypot.
- Check if the [Jitter Algorithm](../networking/network.md#jitter) is set too high (default is 50-300ms).

### Stats Dashboard is Empty
If `stats.py` shows zeros:
- Ensure `stats.enabled: true` is set in `app.yaml`.
- Verify `cyanide-stats.json` is being written to `var/log/cyanide/`.
