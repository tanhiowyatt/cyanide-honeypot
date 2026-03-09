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
- The `ContextAnalyzer` assesses target IPs (identifying public scanners vs internal ranges), referenced VFS paths (identifying attempts to manipulate system bootloaders vs temp storage), and the timing behavior of specific attacker patterns (e.g. executing 10 recon commands in exactly 0.05 seconds indicates bot-like orchestration).
