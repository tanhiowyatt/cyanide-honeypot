import json
import logging
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)


class KnowledgeBase:
    """
    Knowledge Base for classifying commands to MITRE ATT&CK techniques.
    """

    # Function 109: Initializes the class instance and its attributes.
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=10000,
            ngram_range=(2, 4),
            min_df=1,
            max_df=0.98,
            analyzer="char_wb",
            sublinear_tf=True,
            norm="l2",
        )

        self.command_corpus = []
        self.command_metadata = []
        self.technique_db = {}
        self.tactic_db = {}
        self.group_db = {}
        self.malware_db = {}
        self.relationships = {}

        self.tfidf_matrix = None
        self.is_built = False

    # Function 110: Loads data from storage or configuration.
    def load_data(self, kb_dir: Path):
        """Loads all KB data from JSONL files."""
        kb_dir = Path(kb_dir)
        logger.info(f"[*] Loading KB data from {kb_dir}...")

        self._load_mappings(kb_dir)

        self._load_jsonl_db(kb_dir / "mitre_techniques.jsonl", self.technique_db)

        self._load_jsonl_db(kb_dir / "mitre_tactics.jsonl", self.tactic_db)

        self._load_jsonl_db(kb_dir / "mitre_groups.jsonl", self.group_db)

        self._load_jsonl_db(kb_dir / "mitre_malware.jsonl", self.malware_db)

        rel_file = kb_dir / "mitre_relationships.json"
        if rel_file.exists():
            with open(rel_file, "r") as f:
                self.relationships = json.load(f)

        logger.info(
            f"[*] Loaded KB data: {len(self.command_corpus)} commands, {len(self.technique_db)} techniques."
        )

    def _load_mappings(self, kb_dir: Path):
        """Helper to load all mapping files."""
        for filename in ["atomic_red_team_mapping.jsonl", "manual_mappings.jsonl"]:
            mappings_file = kb_dir / filename
            if mappings_file.exists():
                self._load_mapping_file(mappings_file)

    def _load_mapping_file(self, mappings_file: Path):
        """Helper to load a single mapping file."""
        with open(mappings_file, "r") as f:
            for line in f:
                self._process_mapping_line(line)

    def _process_mapping_line(self, line: str):
        """Helper to process a single line from a mapping file."""
        try:
            data = json.loads(line)
            command = data.get("input", "")
            output = data.get("output", "")

            if " - " in output:
                parts = output.split(" - ", 1)
                technique_id = parts[0].strip()
                technique_name = parts[1].strip()
            else:
                return

            self.command_corpus.append(command)
            self.command_metadata.append(
                {
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "metadata": data.get("metadata", {}),
                }
            )
        except (json.JSONDecodeError, IndexError):
            pass

    # Function 111: Performs operations related to load jsonl db.
    def _load_jsonl_db(self, path, db_dict):
        if path.exists():
            with open(path, "r") as f:
                for line in f:
                    try:
                        obj = json.loads(line)
                        if "id" in obj:
                            db_dict[obj["id"]] = obj
                    except json.JSONDecodeError:
                        continue

    # Function 112: Performs operations related to build index.
    def build_index(self):
        """Builds TF-IDF index."""
        if not self.command_corpus:
            logger.warning("[!] No commands to index.")
            return

        logger.info("[*] Building TF-IDF index...")
        self.tfidf_matrix = self.vectorizer.fit_transform(self.command_corpus)
        self.is_built = True
        logger.info(f"[+] Index built: {self.tfidf_matrix.shape}")

    # Function 113: Performs operations related to search.
    def search(self, query_command, top_k=5):
        """Search for similar commands."""
        if not self.is_built:
            return []

        query_vector = self.vectorizer.transform([query_command])
        similarities = cosine_similarity(query_vector, self.tfidf_matrix)[0]
        top_indices = np.argsort(similarities)[-top_k:][::-1]

        results = []
        for idx in top_indices:
            similarity = similarities[idx]
            if similarity < 0.1:
                continue

            metadata = self.command_metadata[idx]
            technique_id = metadata["technique_id"]
            technique_info = self.technique_db.get(technique_id, {})

            result = {
                "matched_command": self.command_corpus[idx],
                "similarity": float(similarity),
                "technique_id": technique_id,
                "technique_name": technique_info.get("name", ""),
                "description": technique_info.get("answer", ""),
                "tactics": technique_info.get("tactics", []),
                "detection": technique_info.get("detection", ""),
                "related_groups": self._get_related_groups(technique_id),
                "related_malware": self._get_related_malware(technique_id),
                "source": metadata.get("metadata", {}).get("source", "unknown"),
            }
            results.append(result)

        results.sort(
            key=lambda x: (x["similarity"], 1 if x["source"] == "manual_mapping" else 0),
            reverse=True,
        )

        return results

    # Function 114: Performs operations related to enrich technique details.
    def _enrich_technique_details(self, technique_id, technique_info):
        """Helper to build full technique context."""
        return {
            "technique": {
                "id": technique_id,
                "name": technique_info.get("name", ""),
                "description": technique_info.get("description", ""),
            },
            "tactics": [{"name": t} for t in technique_info.get("tactics", [])],
            "mitigation": technique_info.get("mitigation", ""),
            "detection": technique_info.get("detection", ""),
            "platforms": technique_info.get("platforms", []),
            "permissions_required": technique_info.get("permissions_required", []),
            "defenses_bypassed": technique_info.get("defenses_bypassed", []),
            "related_groups": self._get_related_groups(technique_id),
            "related_malware": self._get_related_malware(technique_id),
        }

    # Function 115: Performs operations related to enrich technique.
    def enrich_technique(self, technique_id):
        """Public method to get enriched details for a technique ID (used by pipeline)."""
        technique_info = self.technique_db.get(technique_id)
        if not technique_info:
            return None
        return self._enrich_technique_details(technique_id, technique_info)

    # Function 116: Performs operations related to get related groups.
    def _get_related_groups(self, technique_id):
        groups = []
        for rel in self.relationships.get("uses", []):
            if rel.get("target_id") == technique_id and rel.get("source_type") == "group":
                group_info = self.group_db.get(rel["source_id"], {})
                groups.append({"id": rel["source_id"], "name": group_info.get("name", "Unknown")})
        return groups[:5]

    # Function 117: Performs operations related to get related malware.
    def _get_related_malware(self, technique_id):
        malware = []
        for rel in self.relationships.get("uses", []):
            if rel.get("target_id") == technique_id and rel.get("source_type") == "malware":
                mal_info = self.malware_db.get(rel["source_id"], {})
                malware.append({"id": rel["source_id"], "name": mal_info.get("name", "Unknown")})
        return malware[:5]

    # Function 118: Performs operations related to classify command.
    def classify_command(self, command):
        """Classify command and return MITRE context."""
        matches = self.search(command, top_k=3)
        if not matches:
            fallback = self._fallback_classify(command)
            if fallback:
                return fallback
            return {"classified": False, "reason": "No similar commands found"}

        best_match = matches[0]

        if best_match["similarity"] < 0.35:
            fallback = self._fallback_classify(command)
            if fallback:
                return fallback

            return {
                "classified": False,
                "reason": "Low confidence",
                "confidence": best_match["similarity"],
            }

        sim = best_match["similarity"]
        if sim >= 0.7:
            conf_level = "HIGH"
        elif sim >= 0.5:
            conf_level = "MEDIUM"
        else:
            conf_level = "LOW"

        technique_id = best_match["technique_id"]
        technique_info = self.technique_db.get(technique_id, {})

        enriched = self._enrich_technique_details(technique_id, technique_info)

        result = {
            "classified": True,
            "confidence": best_match["similarity"],
            "confidence_level": conf_level,
            **enriched,
        }
        return result

    # Function 119: Performs operations related to fallback classify.
    def _fallback_classify(self, command):
        """Simple keyword matching fallback."""
        command_lower = command.lower()
        keywords = {
            "wget": "T1105",
            "curl": "T1105",
            "nc": "T1059",
            "bash": "T1059",
            "chmod 777": "T1222",
            "chmod +s": "T1548",
            "/etc/shadow": "T1552",
            "/etc/passwd": "T1087",
            "base64": "T1027",
            "crontab": "T1053",
        }

        for kw, tech_id in keywords.items():
            if kw in command_lower:
                tech_info = self.technique_db.get(tech_id, {"name": "Unknown"})
                enriched = self._enrich_technique_details(tech_id, tech_info)
                return {
                    "classified": True,
                    "confidence": 0.3,
                    "confidence_level": "FALLBACK",
                    "match_method": "keyword",
                    "matched_keyword": kw,
                    **enriched,
                }
        return None

    # Function 120: Performs operations related to save.
    def save(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            joblib.dump(
                {
                    "vectorizer": self.vectorizer,
                    "tfidf_matrix": self.tfidf_matrix,
                    "command_corpus": self.command_corpus,
                    "command_metadata": self.command_metadata,
                    "technique_db": self.technique_db,
                    "tactic_db": self.tactic_db,
                    "group_db": self.group_db,
                    "malware_db": self.malware_db,
                    "relationships": self.relationships,
                    "is_built": self.is_built,
                },
                f,
            )
        logger.info(f"[+] KB saved to {path}")

    # Function 121: Performs operations related to load.
    def load(self, path):
        try:
            with open(path, "rb") as f:
                data = joblib.load(f)
                self.__dict__.update(data)
            logger.info(f"[*] KB loaded from {path}")
        except Exception as e:
            logger.error(f"[!] Failed to load KB: {e}")
