[![Stars](https://img.shields.io/github/stars/tanhiowyatt/cyanide?style=flat&logo=GitHub&color=yellow)](https://github.com/tanhiowyatt/cyanide/stargazers)
[![CI](https://github.com/tanhiowyatt/cyanide/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tanhiowyatt/cyanide/actions/workflows/ci.yml)
[![Security Scan](https://github.com/tanhiowyatt/cyanide/actions/workflows/security_scan.yml/badge.svg)](https://github.com/tanhiowyatt/cyanide/actions/workflows/security_scan.yml)


<p align="center">
  <img src="assets/branding/name.png" alt="Cyanide" width="500" height="auto">
</p>

# Cyanide – Medium-Interaction SSH and Telnet Honeypot

**Cyanide** is a medium-interaction SSH and Telnet honeypot designed to deceive attackers and analyze their behavior in depth. It combines realistic Linux filesystem emulation, advanced command simulation (with pipes and redirections), robust anti-detection mechanisms, and a hybrid ML engine for anomaly detection.


---

### Features

#### 1) Machine Learning for Automated Attack Classification and IOC Extraction
- The system automatically categorizes network activity into attack types (brute-force, credential stuffing, reconnaissance, exploit attempts) based on session behavior and payload characteristics.
- Events are normalized with extraction of Indicators of Compromise (IOCs), including IP addresses, ports, credentials, user agents/banners, commands, URLs, artifact hashes, and attacker frequency dictionaries.
- A session summary is generated, detailing the attack intent, deviations from baseline norms, and recommended IOCs for blocking or integration into detection rules.

#### 2) Enhanced Realism to Evade Honeypot Detection
- Realistic timing and response variability (errors, delays, message formats) increase misclassification rates by automated honeypot detectors.
- Dynamic environment profiles: service banners, versions, and operational narratives evolve naturally, avoiding static templates.
- Human-like interface behavior: plausible constraints, error messaging, and minor inconsistencies characteristic of production systems.

#### 3) Advanced SOC and Analytics Integrations
- Structured JSON logs with a standardized event schema to facilitate correlation and search.
- Event export to external systems: SIEM/log stacks (ELK/Splunk), webhook alerts (Slack/Discord/Telegram) for real-time notifications.
- Configurable triggers and rules for critical pattern alerts (e.g., anomalous brute-force velocity, dropper uploads, suspicious commands/payloads).

 ---

### Quick Start 

 ```bash
1. Launch the environment
docker-compose up -d

2. Connect via SSH
ssh root@localhost -p 2222

With Local Changes

docker-compose up -d --build
```
---

### How the Honeypot Works

Cyanide honeypot deploys a **decoy service** and guides attackers through a **controlled scenario**: it emulates a realistic service without granting actual host access.

#### YAML Profiles (Behavior Foundation)
Service behavior is defined via **YAML profiles**:
- Emulated features (banners/versions, errors, constraints);
- Response logic (rules/templates, branching);
- Session state (authentication, context, counters);
- Realism factors (delays/jitter, randomization).

#### MsgPack (Fast Runtime)
YAML serves as the "source code," compiled/cached into **MsgPack** for production:
- Faster loading/decoding than YAML/JSON;
- Smaller footprint, easier caching/distribution;
- More stable high-load performance.

#### Session Flow
1. Incoming event (login/command/payload)  
2. State update  
3. Profile rules application (YAML/MsgPack)  
4. Response generation (with realistic timing)  
5. Logging + IOC extraction

#### Logs and IOCs
Structured events are captured: IP/session ID, login attempts, commands/payloads, timings, and outcomes. From this, **IOCs** are extracted, attacks classified, and alerts/exported to SOC systems.

---

### Creators 
 
This honeypot was created by **tanhiowyatt** and **Koshanzov Nikolay**, the founding contributors to Cyanide Labs. Our initial collaboration on advanced honeypot prototypes evolved into the current suite of open-source cybersecurity tools, focusing on realistic threat simulation, ML-driven attack classification, and seamless SOC integrations.

---

### Disclaimer

This software is for educational and research purposes only. Running a honeypot involves significant risks. The author is not responsible for any damage or misuse.