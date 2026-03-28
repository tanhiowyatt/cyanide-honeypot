# Detection Engine (`src/cyanide/ml`)

The Detection Engine distinguishes Cyanide from primitive honeypots. It combines rigid heuristics with Machine Learning modeling to categorize obfuscated or complex, novel payloads that simple Regex rules would typically miss.

The stack utilizes three complementary layers.

## Layer 1: Security Rule Engine (Deterministic)

The determinism layer (`rules.py`) evaluates session events against a curated set of known malicious signatures.

### Mechanism:
- **Registry:** Matches input command histories via precompiled Regular Expression strings targeting high-profile exploitation tactics.
- **Categorization:** When a pattern matches (e.g., invoking `wget` and piping it into `bash`, or using `iptables -F` to drop firewalls), the engine scores it immediately and associates it with specific MITRE ATT&CK Framework technique mappings.

## Layer 2: ML Autoencoder (Probabilistic)

Attackers continuously mutate their scripts. To identify zero-days or heavily obfuscated payloads (such as commands hidden via Base64 encoding or excessive hex substitution), the engine utilizes Long Short-Term Memory (LSTM) models.

### Mechanism:
- **Tokenization:** Raw commands are converted into numerical sequences at the character level. The embedding maps characters based on their statistical frequency.
- **Reconstruction:** An `AnomalyDetector` class (the Autoencoder) processes this tensor into a compressed state and forces the network to rebuild it.
- **Scoring Function:** Traditional sysadmin commands (e.g., `ls -la`, `ps aux`) reconstruct cleanly with minimal error. Severely obfuscated or chaotic shell commands reconstruct poorly. If the Reconstruction Error (MSE) breaches the dynamic threshold, the payload is flagged as anomalous.

## Layer 3: Context Analysis

Context analysis enriches raw detection outcomes by considering the surrounding operational targets.

### Mechanism:
- If a seemingly benign command (`cat`) is executed against a critically sensitive target (`/etc/shadow`), the semantic consequence is inherently severe.
- **Smart Bot Detection**: The `ContextAnalyzer` assesses the timing behavior of attacker patterns. It calculates a multi-factor **Bot Score** based on keystroke jitter (standard deviation of delays) and "paste" events. A very low standard deviation (even if delays are long) indicates a scripted orchestration, while high variance suggests a human.

## Layer 4: GeoIP Enrichment

Modern threat intel requires geographic context. The `AnalyticsService` seamlessly integrates with IP-based geolocation databases (e.g., MaxMind).
- When a new attacker connects, their source IP is instantly queried against the local GeoIP database.
- Metadata including `Country`, `City`, and `ASN` (Autonomous System Number) is merged into their session context.
- This allows researchers to quickly map botnet origins and correlate behavioral anomalies (from the Autoencoder) directly with geographical threat actor clusters.

## Layer 5: Output Plugins & Central Logging

Identifying a threat is useless if nowhere is alerted. The analytics pipeline standardizes all findings into parsed JSON events and feeds them to the `CyanideLogger`.

### Centralized Logging (`CyanideLogger`)
- Replaces legacy scattering by centralizing all logs into unified, automatically rotated streams (`cyanide-server.json`, `cyanide-ml.json`, etc.).
- Native rotation (`time` or `size`) ensures the honeypot disk never fills up, preventing denial of service by logging exhaustion.

### Output Plugins Architecture
In production, Cyanide can replicate these unified logs via asynchronous output plugins to:
1. **ElasticSearch / Splunk:** For massive SIEM aggregations.
2. **PostgreSQL:** For structured long-term historical analysis.
3. **Slack / Discord:** For real-time, high-priority severity alerts (e.g., when a user drops a confirmed zero-day binary).
4. **HPFeeds:** For sharing anonymous threat feeds with the global Honeynet project community.
