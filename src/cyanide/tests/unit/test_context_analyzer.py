import pytest

from cyanide.ml.context_analyzer import ContextAnalyzer


@pytest.fixture
def analyzer():
    return ContextAnalyzer()


def test_analyze_url_no_url(analyzer):
    result = analyzer.analyze_url("no url here")
    assert result["has_url"] is False
    assert result["risk_score"] == 0.0


def test_analyze_url_safe(analyzer):
    result = analyzer.analyze_url("Check https://github.com/project")
    assert result["has_url"] is True
    assert result["verdict"] == "safe"
    assert result["risk_score"] == 0.0  # Whitelist bonus reduces risk to 0 (max(0.0, ...))


def test_analyze_url_suspicious_ip(analyzer):
    result = analyzer.analyze_url("curl http://1.2.3.4/sh")
    assert result["has_url"] is True
    assert "IP-based URL: 1.2.3.4" in result["flags"]
    assert result["risk_score"] >= 0.4
    assert result["verdict"] == "suspicious"


def test_analyze_url_suspicious_tld(analyzer):
    result = analyzer.analyze_url("visit http://malicious.xyz")
    assert result["has_url"] is True
    assert "Suspicious TLD: .xyz" in result["flags"]
    assert result["risk_score"] >= 0.5
    assert result["verdict"] == "suspicious"


def test_analyze_url_suspicious_keyword(analyzer):
    result = analyzer.analyze_url("download http://example.com/malware.exe")
    assert result["has_url"] is True
    assert "Suspicious keyword: malware" in result["flags"]
    # risk_score: 0.4 (keyword). example.com is not in whitelist.
    assert result["risk_score"] == pytest.approx(0.4)
    assert result["verdict"] == "suspicious"


def test_analyze_url_multiple(analyzer):
    result = analyzer.analyze_url("http://1.2.3.4 and http://malicious.xyz")
    assert result["has_url"] is True
    assert len(result["urls"]) == 2
    # risk scores are added: 0.4 + 0.5 = 0.9 (capped at 1.0)
    assert result["risk_score"] == pytest.approx(0.9)
    assert result["verdict"] == "suspicious"
