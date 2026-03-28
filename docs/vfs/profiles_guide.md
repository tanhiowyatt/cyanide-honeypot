# 🎭 OS Profiles Guide

OS Profiles allow Cyanide to masquerade as different Linux distributions or specialized devices. Every session in `emulated` mode is bound to a specific profile that dictates the filesystem structure and system metadata.

## 📁 Profile Structure

Profiles are located in `configs/profiles/`. A minimal profile requires two files:

```text
configs/profiles/my_device/
├── base.yaml      # Metadata and dynamic behavior
└── static.yaml    # Filesystem layout
```

---

## 1. Metadata (`base.yaml`)

This file defines the "identity" of the target system.

```yaml
metadata:
  os_name: "Ubuntu"
  hostname: "web-server-01"
  kernel_version: "5.15.0-73-generic"
  arch: "x86_64"
  os_id: "ubuntu"
  version_id: "22.04"
```

### Dynamic Files
You can map specific files to **Dynamic Providers** (Python functions) for realistic output:

```yaml
dynamic_files:
  /proc/uptime: { provider: uptime_provider }
  /proc/cpuinfo: { provider: cpuinfo_provider }
```

---

## 2. Filesystem Layout (`static.yaml`)

This file defines every file and directory the attacker will see.

### Inline Content
Use `content` for small text files or configurations. You can use Jinja2 templates to reference metadata.

```yaml
static:
  /etc/issue:
    content: "Welcome to {{ os_name }} {{ version_id }}\n"
    mode: 0644
    owner: root
```

### External Sources
Use `source` to reference large binary files or existing directories on your host.

```yaml
static:
  /bin/ls:
    source: "ubuntu/bin/ls"  # Relative to the profile folder
```

---

## 3. Creating Your First Profile

1. **Create the folder**: `mkdir configs/profiles/iot_camera`
2. **Define base.yaml**: Set the `os_name` to something like "BusyBox" and the `hostname` to "IP-CAMERA-88".
3. **Define static.yaml**: 
   - Add a `/etc/passwd` containing a single `root:x:0:0...` line.
   - Add a `/bin/busybox` source link.
4. **Test it**:
   ```bash
   export CYANIDE_SERVER__OS_PROFILE=iot_camera
   python3 -m cyanide.main
   ```
5. **Verify**: Connect via Telnet and run `cat /etc/issue` or `uname -a`.

---

## ⚡ Performance Optimization
Cyanide automatically compiles your YAML profiles into binary **SQLite** caches (`.compiled.db`) upon the first connection. You do not need to manually manage these; they auto-invalidate whenever you edit your YAML files.
