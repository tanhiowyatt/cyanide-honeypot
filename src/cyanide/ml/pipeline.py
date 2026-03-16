from pathlib import Path

from .classifier import KnowledgeBase
from .context_analyzer import ContextAnalyzer
from .model import CommandAutoencoder
from .rule_engine import SecurityRuleEngine


class CyanideML:
    """
    Main pipeline integrating Anomaly Detector and Knowledge Base.
    Enhanced with Security Rules and Context Analysis (Hybrid Detection).
    """

    # Function 132: Initializes the class instance and its attributes.
    def __init__(self, model_dir="assets/models"):
        self.model_dir = Path(model_dir)
        self.anomaly_detector = CommandAutoencoder.load(self.model_dir / "cyanideML.pkl")

        self.kb = KnowledgeBase()
        self.kb.load(self.model_dir / "knowledge_base.pkl")

        self.rule_engine = SecurityRuleEngine()
        self.context_analyzer = ContextAnalyzer()

    # Function 133: Performs operations related to analyze command.
    def analyze_command(self, command):
        """
        Multi-layer analysis: ML -> Rules -> Context -> Fusion
        """
        is_anomaly_ml, score, error = self.anomaly_detector.predict(command)

        rule_result = self.rule_engine.evaluate(command)

        context_result_url = self.context_analyzer.analyze_url(command)
        context_result_path = self.context_analyzer.analyze_file_paths(command)

        final_verdict = "anomaly" if is_anomaly_ml else "clean"
        final_score = float(score)
        fusion_source = "ml"

        if rule_result["matched"]:
            is_anomaly_ml = True
            final_verdict = "anomaly"
            fusion_source = "rule"
            final_score = max(final_score, rule_result["confidence"])

        context_triggered = False
        context_score = 0.0

        if context_result_url["verdict"] == "suspicious":
            context_triggered = True
            context_score = max(context_score, context_result_url["risk_score"])

        if context_result_path.get("matched"):
            context_triggered = True
            sev_score_map = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.6, "LOW": 0.4}
            path_score = sev_score_map.get(context_result_path["severity"], 0.5)
            context_score = max(context_score, path_score)

        if context_triggered:
            if not rule_result["matched"]:
                if context_score > 0.6:
                    is_anomaly_ml = True
                    final_verdict = "anomaly"
                    fusion_source = "context"
            final_score = max(final_score, context_score)

        classification = None
        severity = "BENIGN"

        if is_anomaly_ml:
            classification = self.kb.classify_command(command)

            if rule_result["matched"] and (
                not classification.get("classified")
                or rule_result["confidence"] > classification.get("confidence", 0)
            ):
                enriched = self.kb.enrich_technique(rule_result["technique"])
                if enriched:
                    classification = {
                        "classified": True,
                        "confidence": rule_result["confidence"],
                        "confidence_level": "HIGH",
                        "match_method": "rule_based",
                        **enriched,
                    }
                else:
                    classification = {
                        "classified": True,
                        "technique": {
                            "id": rule_result["technique"],
                            "name": rule_result["description"],
                            "description": "Identified by Security Rule Engine",
                        },
                        "confidence": rule_result["confidence"],
                        "confidence_level": "HIGH",
                        "match_method": "rule_based",
                    }

            elif context_result_path.get("matched") and not classification.get("classified"):
                tech_id = context_result_path["techniques"][0]
                enriched = self.kb.enrich_technique(tech_id)
                if enriched:
                    classification = {
                        "classified": True,
                        "confidence": 0.8,
                        "confidence_level": "MEDIUM",
                        "match_method": "context_analysis",
                        **enriched,
                    }
                else:
                    classification = {
                        "classified": True,
                        "technique": {
                            "id": tech_id,
                            "name": "Sensitive Path Access",
                            "description": "Access to sensitive system file",
                        },
                        "confidence": 0.8,
                        "confidence_level": "MEDIUM",
                        "match_method": "context_analysis",
                    }

            severity = self._determine_severity(classification)
            if rule_result["matched"]:
                if rule_result["severity"] in ["CRITICAL", "HIGH"]:
                    severity = rule_result["severity"]

        result = {
            "command": command,
            "is_anomaly": is_anomaly_ml,
            "verdict": final_verdict,
            "anomaly_score": final_score,
            "reconstruction_error": float(error),
            "fusion_source": fusion_source,
            "classification": classification,
            "severity": severity,
            "detection_layers": {
                "ml_detected": score > self.anomaly_detector.threshold,
                "rule_match": rule_result["matched"],
                "context_suspicious": context_triggered,
            },
        }
        return result

    # Function 134: Performs operations related to determine severity.
    def _determine_severity(self, classification):
        """
        Determine severity based on MITRE tactics.
        """
        if not classification or not classification.get("classified"):
            return "UNKNOWN"

        tactics = set()
        for t in classification.get("tactics", []):
            if isinstance(t, dict):
                tactics.add(t.get("name", "").lower())
            else:
                tactics.add(str(t).lower())

        if "impact" in tactics:
            return "CRITICAL"

        high_severity = {"exfiltration", "credential-access", "lateral-movement"}
        if tactics & high_severity:
            return "HIGH"

        medium_severity = {
            "command-and-control",
            "persistence",
            "execution",
            "privilege-escalation",
        }
        if tactics & medium_severity:
            return "MEDIUM"

        low_severity = {"defense-evasion", "discovery", "collection", "initial-access"}
        if tactics & low_severity:
            return "LOW"

        return "UNKNOWN"
