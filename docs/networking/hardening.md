# Hardening and Safe Deployment Guide

This guide outlines the recommended security posture and infrastructure requirements for deploying Cyanide in production or internet-facing environments.

## 1. Network Isolation

The most critical aspect of honeypot security is isolation. A compromised honeypot must not become a pivot point for attacking your internal infrastructure.

### VLAN/VPC Isolation
- **DMZ Deployment**: Deploy Cyanide in a dedicated DMZ or an isolated VLAN.
- **VPC Segregation**: In cloud environments (AWS/GCP/Azure), use a separate VPC with no peering to internal resources.
- **Stealth Mode**: Ensure the honeypot host does not respond to ICMP (ping) on the management interface.

### Egress Filtering (Outbound)
Strictly limit the honeypot's ability to "call home" or scan other targets:
- **Default Deny**: Block all outbound traffic by default.
- **Whitelisting**: Only allow outbound connections to:
  - Your centralized logging server (e.g., Syslog, ELK, Splunk).
  - Essential updates (if not using immutable images).
- **Rate Limiting**: Limit the number of outbound connections to prevent the honeypot from participating in DDoS attacks.

## 2. Host and Container Security

### Docker Hardening
Our `docker-compose.yml` includes several security defaults. Do not weaken them:
- **Read-Only Filesystem**: The root filesystem is enforced as strictly `read_only`. This means the container itself is immutable.
- **Writable Volumes**: The only areas where the honeypot can write data are explicitly mounted volumes:
  - `/app/configs` (for configuration overrides or dynamic profiles)
  - `/app/var/log/cyanide` (for honeypot logs and audit trails)
  - `/app/var/quarantine` (for capturing malware artifacts)
  - `/app/var/lib/cyanide` (for persistent application state)
  - `tmpfs` at `/tmp` (used for temporary runtime files only)
- **No New Privileges**: Specifically prevents the container processes from gaining new privileges via `setuid` binaries (`security_opt: [no-new-privileges:true]`).
- **Capability Dropping**: All Linux capabilities are dropped (`cap_drop: [ALL]`).
- **Resource Limits**: Memory (e.g., 512M) and CPU (e.g., 0.5) limits prevent DoS of the host machine by a rogue container.

### Host Protection
- **Dedicated Host**: Never run a honeypot on a host that performs other critical functions.
- **Immutable OS**: Consider using a minimized, hardened OS like Fedora CoreOS or Alpine Linux.
- **Update Policy**: Use automated updates for the host kernel and Docker engine.

## 3. Logging and Monitoring

### Remote Logging
- **Do not store logs exclusively on the honeypot**. If an attacker compromises the container, they will delete the audit trail.
- Mirror all logs to a remote, write-only Syslog or ELK stack.
- Monitor for `session.end` events without corresponding `session.start` (potential crash or evasion).

### Alerting
Set up alerts for the following triggers:
- **Malware Detected**: High-fidelity signal of active exploitation.
- **Honeytoken Triggered**: High-priority alert indicating the attacker has accessed sensitive "planted" files.
- **Container Health Failures**: Indicates potential DoS or crash of the honeypot services.

## 4. Key Management and Rotation

- **SSH Host Keys**: Rotate host keys periodically.
- **API Keys**: Use Docker Secrets or environment variable injection for VirusTotal or OpenAI keys. Never hardcode them in images.
- **SSH Credentials**: Rotate the "honeypot" user passwords frequently to keep the environment fresh for new attackers.

## 5. Deployment Checklist

1. [ ] Is the container running as a non-root user? (Check `USER cyanide` in Dockerfile)
2. [ ] Are resource limits enforced?
3. [ ] Is egress traffic blocked except for logging/metrics?
4. [ ] Are logs being shipped to a remote server?
5. [ ] Is the management interface (SSH/Web) restricted to your IP/VPN only?
