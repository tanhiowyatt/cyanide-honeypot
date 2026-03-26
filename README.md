<p align="center">

  [![Stars](https://img.shields.io/github/stars/tanhiowyatt/cyanide?style=flat&logo=GitHub&color=yellow)](https://github.com/tanhiowyatt/cyanide/stargazers)
  [![CI](https://github.com/tanhiowyatt/cyanide/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tanhiowyatt/cyanide/actions/workflows/ci.yml)
  [![Security Scan](https://github.com/tanhiowyatt/cyanide/actions/workflows/security_scan.yml/badge.svg)](https://github.com/tanhiowyatt/cyanide/actions/workflows/security_scan.yml)
  [![Quality gate](https://sonarcloud.io/api/project_badges/measure?project=tanhiowyatt_cyanide&metric=alert_status)](https://sonarcloud.io/dashboard?id=tanhiowyatt_cyanide)
  [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=tanhiowyatt_cyanide&metric=coverage)](https://sonarcloud.io/component_measures/metric/coverage/list?id=tanhiowyatt_cyanide)
  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
  [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/)
</p>


<p align="center">
  <a target="_blank" href="/docs/translations/readme-ru.md">RU</a> &nbsp; | &nbsp;
  <a target="_blank" href="/docs/translations/readme-pl.md">PL</a>
</p>

<p align="center">
  <img src="src/cyanide/assets/branding/name.png" alt="Cyanide" width="500" height="auto">
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
1. Clone the repository
git clone https://github.com/tanhiowyatt/cyanide.git

2. Go in docker folder
cd cyanide

3. Launch the environment
docker-compose up -d

4. Connect via SSH, Telnet or SFTP
ssh root@localhost -p 2222 or 
telnet localhost -p 2222 or 
sftp root@localhost -p 2222

* With Local Changes
docker-compose up -d --build
```

### Quick Start via PyPI

```bash
1. Install the package
pip install cyanide

2. Run the honeypot
cyanide
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

#### SQLite (Fast Runtime)
YAML serves as the "source code," compiled/cached into **SQLite** (`.compiled.db`) for production:
- Faster loading/decoding than YAML/JSON;
- Smaller footprint, easier caching/distribution;
- More stable high-load performance.

#### Session Flow
1. Incoming event (login/command/payload)  
2. State update  
3. Profile rules application (YAML/SQLite)  
4. Response generation (with realistic timing)  
5. Logging + IOC extraction

#### Logs and IOCs
Structured events are captured: IP/session ID, login attempts, commands/payloads, timings, and outcomes. From this, **IOCs** are extracted, attacks classified, and alerts/exported to SOC systems.

---

### Creators 
 
This honeypot was created by **tanhiowyatt** and **koshanzov**. Our initial collaboration on advanced honeypot prototypes evolved into the current open-source cybersecurity project, focusing on realistic threat simulation, ML-driven attack classification, and seamless SOC integration.

---

### Disclaimer

This software is for educational and research purposes only. Running a honeypot involves significant risks. The author is not responsible for any damage or misuse.