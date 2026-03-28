# 🚀 Deployment Guide

Cyanide is designed to be highly portable, supporting both containerized environments and traditional baremetal installations.

## 🐳 Docker Deployment (Recommended)

Docker is the preferred way to run Cyanide, as it provides seamless isolation and consistent dependency management.

### 1. Prerequisites
- Docker and Docker Compose installed.
- (Optional) Libvirt/KVM if using `pool` mode on the host.

### 2. Standard Stack
The default stack includes the honeypot, a local MailHog instance (for SMTP capturing), and Jaeger (for distributed tracing).

```bash
# Clone and enter the repository
git clone https://github.com/tanhiowyatt/cyanide-honeypot.git
cd cyanide

# Launch the stack
docker-compose -f deployments/docker/docker-compose.yml up --build -d
```

### 3. Monitoring
- **Logs**: `docker logs -f cyanide`
- **Stats**: `docker exec -it cyanide python3 scripts/management/stats.py`

---

## 🐍 Baremetal Installation

For development or specialized performance tuning, you can run Cyanide directly on a Linux host.

### 1. Setup Environment
Python 3.10+ is required.

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -e .
```

### 2. Install "Extras"
Depending on your configuration, you may need additional libraries:
- **ML Support**: `pip install .[ml]`
- **Output Plugins**: `pip install .[outputs]` (Installs drivers for Postgres, Mongo, etc.)
- **Libvirt Pool**: `pip install .[libvirt]`

### 3. Running
```bash
# Start the server using the default configuration
python3 -m cyanide.main
```

---

## 🏗️ Scaling to Production

### Multiple Sensors
Cyanide is stateless per session. You can deploy multiple "Sensing Nodes" behind a Load Balancer (like HAProxy or Nginx).
- Centralize your logs via the **[ElasticSearch or Splunk plugins](../tooling/plugins.md)**.
- Use a central **PostgreSQL** or **MySQL** database for aggregated metrics.

### Backend VM Pool
When using `backend_mode: pool`, ensure the host running Cyanide has sufficient RAM and CPU to support the `max_vms` parameter. Use `libvirt` on a dedicated virtualization server for the most realistic and secure experience.
