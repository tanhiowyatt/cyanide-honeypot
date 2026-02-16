# Configuration Guide

Cyanide uses a hierarchical configuration system:
1.  **Defaults** (Hardcoded in `src/cyanide/core/defaults.py`)
2.  **YAML Config** (`configs/app.yaml`)
3.  **Environment Variables** (Docker / Shell overrides)

---

## 1. Main Configuration (`configs/app.yaml`)

This file controls the behavior of the honeypot services, logging, and ML engine.

### Server & Network
```yaml
server:
  host: 0.0.0.0       # Bind address
  max_sessions: 100   # Global session limit
  session_timeout: 300 # Seconds before auto-disconnect
```

### Services
Enable or disable protocols:
```yaml
ssh:
  enabled: true
  listen_port: 2222
  backend_mode: emulated # 'emulated' (default) or 'proxy'

telnet:
  enabled: true
  listen_port: 2223

smtp:
  enabled: true      # Enable SMTP Trap
  target_host: mailhog # Forward emails to this host (e.g. MailHog container)
  target_port: 1025
```

### ML & Detection
```yaml
ml:
  enabled: true
  model_path: assets/models/cyanideML.pkl
  retraining_interval_days: 7
```

---

## 2. Filesystem Profiles (`configs/profiles/`)

Cyanide loads its fake filesystem from YAML profiles. This allows it to mimic different OS distributions realistically.

### Structure
Each `fs.*.yaml` file contains:
1.  **Metadata**: System banners and kernel versions.
2.  **Root Node**: A recursive definition of directories and files.

**Example (`fs.ubuntu_22_04.yaml`):**
```yaml
metadata:
  os_name: "Ubuntu 22.04 LTS"
  ssh_banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
  uname_r: "5.15.0-76-generic"

name: root
type: directory
perm: drwxr-xr-x
children:
  - name: etc
    type: directory
    children:
      - name: hostname
        type: file
        content: "server01\n"
```

### Creating a Custom Profile
1.  Copy `configs/fs.yaml.example` to `configs/profiles/fs.my_custom_os.yaml`.
2.  Edit the metadata and file structure.
3.  (Optional) Set `server.os_profile: my_custom_os` in `app.yaml` or just use `random`.

---

## 3. Environment Variables (Docker)

All `app.yaml` keys can be overridden using environment variables with the `CYANIDE_` prefix and double underscores `__` for nesting.

**Examples:**
*   `server.host` -> `CYANIDE_SERVER__HOST`
*   `ssh.listen_port` -> `CYANIDE_SSH__LISTEN_PORT`
*   `ml.enabled` -> `CYANIDE_ML__ENABLED`

See `deployments/docker/docker-compose.yml` for a practical example of how these are used to inject configuration into the container.
