# 🧠 Machine Learning & Analytics Documentation

Cyanide is more than just a interactive shell; it is an intelligent capture system. This section explains the logic behind its hybrid detection engine.

## 📄 Overview
The analytics layer provides real-time threat detection and classification. Instead of simple log collection, Cyanide analyzes commands for malicious patterns using a combination of static rules and neural network anomaly detection.

## 🛠️ How it Works
1.  **Rule Engine**: A fast, regex-based signature matcher for known threats.
2.  **ML Autoencoder**: Learns common shell patterns and scores deviations (high score = anomaly).
3.  **Context Analysis**: Weighs events based on session progression (e.g. sequence of `wget` -> `chmod` -> execution).

## ⚙️ Configuration
The thresholds for anomaly scoring and the specific rules to apply are defined in `configs/app.yaml` under the `ml` and `analytics` blocks. For more info, see the **[Configuration Guide](../core/configuration.md)**.

## 📑 Detailed Documents

*   **[ML & Analytics Overview](ml.md)**: Introduction to the anomaly detection and forensic pipelines.
*   **[Security Rule Engine](ml.md#2-rule-engine)**: Detailed signatures for common attack sequences and binary download patterns.
*   **[Context Analysis](ml.md#3-context-analyzer)**: How Cyanide uses session metadata for real-time risk assessment.
*   **[VirusTotal Integration](ml.md#4-forensics-and-malware-scanning)**: Automated file quarantine and cloud-based file reputation checks.

## 🔗 See Also
*   🔧 **[Operations Guide](../tooling/index.md#statistics-and-dashboards)**: Operationalizing the threat output.
*   🧪 **[Test Data](../tests/index.md)**: Using malicious samples for training and validation.

---
*Last updated: 2026-03-10*
