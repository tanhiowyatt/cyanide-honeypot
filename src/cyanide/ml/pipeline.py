from pathlib import Path
from typing import Optional

from .classifier import KnowledgeBase
from .context_analyzer import ContextAnalyzer
from .model import CommandAutoencoder
from .rule_engine import SecurityRuleEngine


class CyanideML:
    """
    Main pipeline integrating Anomaly Detector and Knowledge Base.
    Enhanced with Security Rules and Context Analysis (Hybrid Detection).
    """

    def __init__(self, model_dir="assets/models"):
        self.model_dir = Path(model_dir)
        self.anomaly_detector = CommandAutoencoder.load(self.model_dir / "cyanideML.pkl")

        self.kb = KnowledgeBase()
        self.kb.load(self.model_dir / "knowledge_base.pkl")

        self.rule_engine = SecurityRuleEngine()
        self.context_analyzer = ContextAnalyzer()

    def analyze_command(self, command):
        """
        Multi-layer analysis: ML -> Rules -> Context -> Fusion
        """
        is_anomaly_ml, score, error = self.anomaly_detector.predict(command)
        rule_result = self.rule_engine.evaluate(command)
        context_results = self._get_context_results(command)

        is_anomaly, verdict, final_score, source, context_triggered = self._fusion_analysis(
            is_anomaly_ml, float(score), rule_result, context_results
        )

        classification, severity = self._get_classification(
            command, is_anomaly, rule_result, context_results["path"]
        )

        return {
            "command": command,
            "is_anomaly": is_anomaly,
            "verdict": verdict,
            "anomaly_score": final_score,
            "reconstruction_error": float(error),
            "fusion_source": source,
            "classification": classification,
            "severity": severity,
            "detection_layers": {
                "ml_detected": score > self.anomaly_detector.threshold,
                "rule_match": rule_result["matched"],
                "context_suspicious": context_triggered,
            },
        }

    def _get_context_results(self, command) -> dict:
        """Collect context analysis results for URLs and file paths."""
        return {
            "url": self.context_analyzer.analyze_url(command),
            "path": self.context_analyzer.analyze_file_paths(command),
        }

    def _fusion_analysis(
        self, is_anomaly_ml: bool, score: float, rule_result: dict, context_results: dict
    ) -> tuple[bool, str, float, str, bool]:
        """Combine ML, rules, and context detections into a final verdict."""
        verdict = "anomaly" if is_anomaly_ml else "clean"
        source = "ml"
        final_score = score

        if rule_result["matched"]:
            is_anomaly_ml = True
            verdict = "anomaly"
            source = "rule"
            final_score = max(final_score, rule_result["confidence"])

        context_triggered = False
        context_score = 0.0

        if context_results["url"]["verdict"] == "suspicious":
            context_triggered = True
            context_score = max(context_score, context_results["url"]["risk_score"])

        path_res = context_results["path"]
        if path_res.get("matched"):
            context_triggered = True
            sev_map = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.6, "LOW": 0.4}
            context_score = max(context_score, sev_map.get(path_res["severity"], 0.5))

        if context_triggered:
            if not rule_result["matched"] and context_score > 0.6:
                is_anomaly_ml = True
                verdict = "anomaly"
                source = "context"
            final_score = max(final_score, context_score)

        return is_anomaly_ml, verdict, final_score, source, context_triggered

    def _get_classification(
        self, command: str, is_anomaly: bool, rule_result: dict, context_result_path: dict
    ) -> tuple[Optional[dict], str]:
        """Determine final classification and severity for anomalous commands."""
        if not is_anomaly:
            return None, "BENIGN"

        classification = self.kb.classify_command(command)

        # Priority 1: Rule-based enrichment
        if rule_result["matched"] and (
            not classification.get("classified")
            or rule_result["confidence"] > classification.get("confidence", 0)
        ):
            classification = self._format_kb_entry(
                rule_result["technique"],
                rule_result["confidence"],
                "rule_based",
                rule_result["description"],
            )

        # Priority 2: Context-based enrichment
        elif context_result_path.get("matched") and not classification.get("classified"):
            classification = self._format_kb_entry(
                context_result_path["techniques"][0],
                0.8,
                "context_analysis",
                "Sensitive Path Access",
            )

        severity = self._determine_severity(classification)
        if rule_result["matched"] and rule_result["severity"] in ["CRITICAL", "HIGH"]:
            severity = rule_result["severity"]

        return classification, severity

    def _format_kb_entry(
        self, tech_id: str, confidence: float, method: str, fallback_name: str
    ) -> dict:
        """Format a classification entry, optionally enriched from knowledge base."""
        enriched = self.kb.enrich_technique(tech_id)
        if enriched:
            return {
                "classified": True,
                "confidence": confidence,
                "confidence_level": "HIGH" if confidence > 0.8 else "MEDIUM",
                "match_method": method,
                **enriched,
            }
        return {
            "classified": True,
            "technique": {
                "id": tech_id,
                "name": fallback_name,
                "description": "Identified by Security Engine",
            },
            "confidence": confidence,
            "confidence_level": "HIGH" if confidence > 0.8 else "MEDIUM",
            "match_method": method,
        }

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
