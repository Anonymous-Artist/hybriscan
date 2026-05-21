"""
tests/test_reporter.py
──────────────────────
Unit tests for core/reporter.py.

Run with:  pytest tests/test_reporter.py -v
"""

import json
import pytest
from pathlib import Path

from core.analyzer import (
    AnalysisResult, TitleInfo, HeaderAudit,
    FormInfo, FormField, ScriptInfo, KeywordInfo,
)
from core.detector import DetectionResult, Category, PatternMatch
from core.reporter import (
    Reporter, ReporterConfig,
    _meta, _endpoint_record, _severity_breakdown,
    _category_aggregation, _top_findings, _summary,
    _risk_summary, _header_frequency, _url_slug,
)
from core.scanner import ScanResult
from core.scorer import ScoringResult, Severity, Label


# ─── Fixtures ─────────────────────────────────────────────────────────────────

BASE_CONFIG = {
    "reporting": {
        "output_dir":            "reports",
        "format":                "json",
        "include_score_vectors": True,
        "include_timing":        True,
        "verbose":               False,
    },
    "logging": {"level": "WARNING", "log_to_file": False},
}

TARGET = "http://target.local"


def _sr_raw(url: str = TARGET, status: int = 200,
            elapsed: float = 15.0, error: str | None = None) -> ScanResult:
    return ScanResult(
        url=url, status_code=None if error else status,
        headers={}, body="", elapsed_ms=elapsed,
        redirected_url=None, error=error,
    )


def _det(url: str, scores: dict[str, float],
         patterns: list[PatternMatch] | None = None) -> DetectionResult:
    cats = {c.value: 0.0 for c in Category}
    cats.update(scores)
    comp = max(cats.values())
    dom = max(cats, key=lambda k: cats[k]) if comp > 0 else None
    return DetectionResult(
        url=url, category_scores=cats, composite_score=comp,
        dominant_category=dom, matched_patterns=patterns or [],
        scan_result=_sr_raw(url),
    )


def _ana(url: str = TARGET, missing: list[str] | None = None,
         insecure: dict | None = None, forms: list | None = None) -> AnalysisResult:
    return AnalysisResult(
        url=url, status_code=200,
        title=TitleInfo(raw="", lower=""),
        forms=forms or [],
        headers=HeaderAudit(
            present={},
            missing=missing or [],
            insecure_values=insecure or {},
        ),
        scripts=ScriptInfo(),
        keywords=KeywordInfo(),
    )


def _make_sr(
    url: str = TARGET,
    composite: float = 0.0,
    severity: Severity = Severity.NONE,
    label: Label = Label.BENIGN,
    dominant: str | None = None,
    cat_scores: dict | None = None,
    missing_headers: list | None = None,
    patterns: list[PatternMatch] | None = None,
) -> ScoringResult:
    cats = {c.value: 0.0 for c in Category}
    if cat_scores:
        cats.update(cat_scores)
    return ScoringResult(
        url=url,
        category_scores=cats,
        composite_score=composite,
        severity=severity,
        label=label,
        confidence=0.8 if label == Label.VULNERABLE else 0.2,
        dominant_category=dominant,
        analyser_bonuses={c.value: 0.0 for c in Category},
        threshold_used=0.70,
        detection_result=_det(url, cat_scores or {}, patterns),
        analysis_result=_ana(url, missing=missing_headers),
    )


def _vuln(url: str = TARGET, composite: float = 0.80,
          dominant: str = "admin") -> ScoringResult:
    return _make_sr(url=url, composite=composite, severity=Severity.HIGH,
                    label=Label.VULNERABLE, dominant=dominant,
                    cat_scores={dominant: composite})


def _benign(url: str = TARGET) -> ScoringResult:
    return _make_sr(url=url, composite=0.05, severity=Severity.NONE,
                    label=Label.BENIGN)


def _reporter() -> Reporter:
    return Reporter(BASE_CONFIG)


# ─── _url_slug ────────────────────────────────────────────────────────────────

def test_url_slug_basic():
    assert _url_slug("http://target.local") == "target.local"


def test_url_slug_with_port():
    assert _url_slug("http://target.local:8080") == "target.local_8080"


def test_url_slug_fallback_on_empty():
    assert _url_slug("") == "scan"


# ─── _meta ────────────────────────────────────────────────────────────────────

def test_meta_contains_required_keys():
    m = _meta("http://t.local", 10, 0.70, "2024-01-01T00:00:00Z", "2024-01-01T00:01:00Z")
    for key in ("hybriscan_version", "target_url", "started_at", "finished_at",
                "endpoints_scanned", "threshold_used"):
        assert key in m


def test_meta_target_url():
    m = _meta("http://t.local", 5, 0.70, "s", "f")
    assert m["target_url"] == "http://t.local"


def test_meta_endpoint_count():
    m = _meta("http://t.local", 42, 0.70, "s", "f")
    assert m["endpoints_scanned"] == 42


def test_meta_threshold_rounded():
    m = _meta("http://t.local", 1, 0.7941234, "s", "f")
    assert m["threshold_used"] == 0.7941


# ─── _endpoint_record ─────────────────────────────────────────────────────────

def test_endpoint_record_required_keys():
    sr = _vuln()
    rec = _endpoint_record(sr, include_vectors=True, include_timing=True)
    for key in ("url", "status_code", "label", "severity", "composite_score",
                "confidence", "dominant_category", "evidence",
                "missing_headers", "insecure_headers", "forms"):
        assert key in rec, f"Missing key: {key}"


def test_endpoint_record_url():
    sr = _vuln("http://t.local/admin/")
    rec = _endpoint_record(sr, True, True)
    assert rec["url"] == "http://t.local/admin/"


def test_endpoint_record_label_is_string():
    sr = _vuln()
    rec = _endpoint_record(sr, True, True)
    assert rec["label"] == "vulnerable"


def test_endpoint_record_severity_is_string():
    sr = _vuln()
    rec = _endpoint_record(sr, True, True)
    assert isinstance(rec["severity"], str)


def test_endpoint_record_vectors_included():
    sr = _vuln()
    rec = _endpoint_record(sr, include_vectors=True, include_timing=True)
    assert "category_scores" in rec
    assert "analyser_bonuses" in rec


def test_endpoint_record_vectors_excluded():
    sr = _vuln()
    rec = _endpoint_record(sr, include_vectors=False, include_timing=True)
    assert "category_scores" not in rec
    assert "analyser_bonuses" not in rec


def test_endpoint_record_timing_included():
    sr = _vuln()
    rec = _endpoint_record(sr, include_vectors=True, include_timing=True)
    assert "elapsed_ms" in rec


def test_endpoint_record_timing_excluded():
    sr = _vuln()
    rec = _endpoint_record(sr, include_vectors=True, include_timing=False)
    assert "elapsed_ms" not in rec


def test_endpoint_record_missing_headers_list():
    sr = _make_sr(missing_headers=["csp", "xfo"])
    rec = _endpoint_record(sr, True, True)
    assert rec["missing_headers"] == ["csp", "xfo"]


def test_endpoint_record_evidence_from_patterns():
    pm = PatternMatch(category="admin", description="WordPress admin path",
                      weight=0.95, match_text="/wp-admin/")
    sr = _make_sr(patterns=[pm])
    rec = _endpoint_record(sr, True, True)
    assert len(rec["evidence"]) == 1
    assert rec["evidence"][0]["description"] == "WordPress admin path"


def test_endpoint_record_evidence_no_raw_match_text():
    """Evidence records must not expose raw match_text in default output."""
    pm = PatternMatch(category="sqli", description="MySQL error",
                      weight=0.95, match_text="SELECT * FROM users WHERE")
    sr = _make_sr(patterns=[pm])
    rec = _endpoint_record(sr, True, True)
    for ev in rec["evidence"]:
        assert "match_text" not in ev


# ─── _severity_breakdown ──────────────────────────────────────────────────────

def test_severity_breakdown_all_keys_present():
    results = [_vuln(), _benign()]
    bd = _severity_breakdown(results)
    for sev in Severity:
        assert sev.value in bd


def test_severity_breakdown_counts():
    results = [
        _make_sr(severity=Severity.CRITICAL, label=Label.VULNERABLE),
        _make_sr(severity=Severity.HIGH,     label=Label.VULNERABLE),
        _make_sr(severity=Severity.NONE,     label=Label.BENIGN),
    ]
    bd = _severity_breakdown(results)
    assert bd["critical"] == 1
    assert bd["high"] == 1
    assert bd["none"] == 1


def test_severity_breakdown_sums_to_total():
    results = [_vuln(), _benign(), _benign()]
    bd = _severity_breakdown(results)
    assert sum(bd.values()) == 3


# ─── _category_aggregation ────────────────────────────────────────────────────

def test_category_aggregation_all_categories_present():
    agg = _category_aggregation([_vuln()])
    for cat in Category:
        assert cat.value in agg


def test_category_aggregation_max_score():
    sr1 = _make_sr(cat_scores={"admin": 0.60})
    sr2 = _make_sr(cat_scores={"admin": 0.85})
    agg = _category_aggregation([sr1, sr2])
    assert agg["admin"]["max_score"] == pytest.approx(0.85)


def test_category_aggregation_dominant_count():
    results = [
        _make_sr(dominant="sqli",  cat_scores={"sqli": 0.70}),
        _make_sr(dominant="sqli",  cat_scores={"sqli": 0.65}),
        _make_sr(dominant="admin", cat_scores={"admin": 0.80}),
    ]
    agg = _category_aggregation(results)
    assert agg["sqli"]["dominant_count"]  == 2
    assert agg["admin"]["dominant_count"] == 1


def test_category_aggregation_nonzero_count():
    results = [
        _make_sr(cat_scores={"admin": 0.50}),
        _make_sr(cat_scores={"admin": 0.0}),
        _make_sr(cat_scores={"admin": 0.30}),
    ]
    agg = _category_aggregation(results)
    assert agg["admin"]["nonzero_count"] == 2


# ─── _top_findings ────────────────────────────────────────────────────────────

def test_top_findings_only_vulnerable():
    results = [_vuln(), _benign(), _benign()]
    top = _top_findings(results)
    assert all(f["severity"] != "none" for f in top)
    assert len(top) == 1


def test_top_findings_ordered_by_score_desc():
    results = [
        _make_sr(url="http://t.local/a", composite=0.60, severity=Severity.HIGH,
                 label=Label.VULNERABLE, dominant="admin"),
        _make_sr(url="http://t.local/b", composite=0.90, severity=Severity.CRITICAL,
                 label=Label.VULNERABLE, dominant="sqli"),
    ]
    top = _top_findings(results)
    assert top[0]["url"] == "http://t.local/b"
    assert top[1]["url"] == "http://t.local/a"


def test_top_findings_respects_n_limit():
    results = [_vuln(url=f"http://t.local/p{i}") for i in range(15)]
    top = _top_findings(results, n=10)
    assert len(top) == 10


def test_top_findings_empty_on_all_benign():
    results = [_benign() for _ in range(5)]
    assert _top_findings(results) == []


def test_top_findings_required_keys():
    results = [_vuln()]
    top = _top_findings(results)
    for key in ("url", "severity", "composite_score", "dominant_category"):
        assert key in top[0]


# ─── _summary ─────────────────────────────────────────────────────────────────

def test_summary_keys():
    s = _summary([_vuln(), _benign()])
    for key in ("total_endpoints", "vulnerable_count", "benign_count",
                "average_score", "max_score", "severity_breakdown", "top_findings"):
        assert key in s


def test_summary_counts():
    s = _summary([_vuln(), _benign(), _benign()])
    assert s["total_endpoints"]  == 3
    assert s["vulnerable_count"] == 1
    assert s["benign_count"]     == 2


def test_summary_max_score():
    results = [_make_sr(composite=0.40), _make_sr(composite=0.80)]
    s = _summary(results)
    assert s["max_score"] == pytest.approx(0.80)


def test_summary_average_score():
    results = [_make_sr(composite=0.20), _make_sr(composite=0.60)]
    s = _summary(results)
    assert s["average_score"] == pytest.approx(0.40)


def test_summary_empty_results():
    s = _summary([])
    assert s["total_endpoints"] == 0
    assert s["average_score"]   == 0.0


# ─── _header_frequency ────────────────────────────────────────────────────────

def test_header_frequency_counts():
    results = [
        _make_sr(missing_headers=["csp", "xfo"]),
        _make_sr(missing_headers=["csp"]),
        _make_sr(missing_headers=[]),
    ]
    freq = _header_frequency(results)
    assert freq["csp"] == 2
    assert freq["xfo"] == 1


def test_header_frequency_sorted_desc():
    results = [
        _make_sr(missing_headers=["a"]),
        _make_sr(missing_headers=["b", "a"]),
        _make_sr(missing_headers=["b", "a", "c"]),
    ]
    freq = _header_frequency(results)
    values = list(freq.values())
    assert values == sorted(values, reverse=True)


def test_header_frequency_empty():
    assert _header_frequency([_make_sr(missing_headers=[])]) == {}


# ─── Reporter.build ───────────────────────────────────────────────────────────

def test_build_returns_dict():
    r = _reporter()
    report = r.build([_vuln(), _benign()], TARGET)
    assert isinstance(report, dict)


def test_build_top_level_keys():
    r = _reporter()
    report = r.build([_vuln()], TARGET)
    for key in ("meta", "summary", "endpoints", "risk_summary"):
        assert key in report


def test_build_endpoints_sorted_desc():
    r = _reporter()
    results = [
        _make_sr(url="http://t.local/a", composite=0.30),
        _make_sr(url="http://t.local/b", composite=0.80, label=Label.VULNERABLE,
                 severity=Severity.HIGH, dominant="admin"),
        _make_sr(url="http://t.local/c", composite=0.10),
    ]
    report = r.build(results, TARGET)
    scores = [e["composite_score"] for e in report["endpoints"]]
    assert scores == sorted(scores, reverse=True)


def test_build_endpoint_count_matches():
    r = _reporter()
    results = [_vuln(), _benign(), _benign()]
    report = r.build(results, TARGET)
    assert len(report["endpoints"]) == 3


def test_build_meta_target_url():
    r = _reporter()
    report = r.build([_benign()], "http://target.local")
    assert report["meta"]["target_url"] == "http://target.local"


def test_build_summary_embedded():
    r = _reporter()
    report = r.build([_vuln(), _benign()], TARGET)
    assert report["summary"]["total_endpoints"] == 2
    assert report["summary"]["vulnerable_count"] == 1


def test_build_timestamps_present():
    r = _reporter()
    report = r.build([_benign()], TARGET,
                     started_at="2024-01-01T10:00:00Z",
                     finished_at="2024-01-01T10:05:00Z")
    assert report["meta"]["started_at"]  == "2024-01-01T10:00:00Z"
    assert report["meta"]["finished_at"] == "2024-01-01T10:05:00Z"


def test_build_empty_results():
    r = _reporter()
    report = r.build([], TARGET)
    assert report["summary"]["total_endpoints"] == 0
    assert report["endpoints"] == []


# ─── Reporter.to_json ─────────────────────────────────────────────────────────

def test_to_json_returns_valid_json():
    r = _reporter()
    report = r.build([_vuln()], TARGET)
    raw = r.to_json(report)
    parsed = json.loads(raw)
    assert parsed["meta"]["target_url"] == TARGET


def test_to_json_is_indented():
    r = _reporter()
    raw = r.to_json(r.build([_benign()], TARGET))
    assert "\n" in raw   # indented output has newlines


# ─── Reporter.save ────────────────────────────────────────────────────────────

def test_save_creates_file(tmp_path):
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    r = Reporter(cfg)
    report = r.build([_vuln()], TARGET)
    path = r.save(report)
    assert path.exists()
    assert path.suffix == ".json"


def test_save_file_is_valid_json(tmp_path):
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    r = Reporter(cfg)
    report = r.build([_benign()], TARGET)
    path = r.save(report)
    with open(path) as f:
        data = json.load(f)
    assert "meta" in data


def test_save_custom_filename(tmp_path):
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    r = Reporter(cfg)
    report = r.build([_benign()], TARGET)
    path = r.save(report, filename="custom_report.json")
    assert path.name == "custom_report.json"


def test_save_creates_output_dir(tmp_path):
    nested = tmp_path / "deep" / "nested"
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(nested)}}
    r = Reporter(cfg)
    report = r.build([_benign()], TARGET)
    r.save(report)
    assert nested.exists()


def test_save_filename_contains_slug(tmp_path):
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    r = Reporter(cfg)
    report = r.build([_benign()], "http://target.local")
    path = r.save(report)
    assert "target.local" in path.name


# ─── to_html placeholder ──────────────────────────────────────────────────────

def test_to_html_raises_not_implemented():
    r = _reporter()
    with pytest.raises(NotImplementedError):
        r.to_html({})


# ─── Score vector config ──────────────────────────────────────────────────────

def test_no_score_vectors_when_disabled():
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "include_score_vectors": False}}
    r = Reporter(cfg)
    report = r.build([_vuln()], TARGET)
    for ep in report["endpoints"]:
        assert "category_scores" not in ep


def test_no_timing_when_disabled():
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "include_timing": False}}
    r = Reporter(cfg)
    report = r.build([_vuln()], TARGET)
    for ep in report["endpoints"]:
        assert "elapsed_ms" not in ep
