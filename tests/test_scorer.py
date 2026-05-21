"""
tests/test_scorer.py
────────────────────
Unit tests for core/scorer.py.

Run with:  pytest tests/test_scorer.py -v
"""

import math
import pytest

from core.analyzer import (
    AnalysisResult, TitleInfo, HeaderAudit,
    FormInfo, FormField, ScriptInfo, KeywordInfo,
)
from core.detector import DetectionResult, Category, PatternMatch
from core.scanner import ScanResult
from core.scorer import (
    Scorer, ScoringResult, ScoringConfig,
    Severity, Label,
    _severity, _confidence, _parse_config,
    _SEVERITY_BANDS,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

BASE_CONFIG = {
    "scoring": {
        "initial_threshold": 0.70,
        "min_threshold":     0.50,
        "max_threshold":     0.82,
        "target_fpr":        0.15,
        "target_accuracy":   0.75,
        "max_iterations":    30,
        "aggregation":       "max_pool",
    },
    "detection": {
        "category_weights": {c.value: 1.0 for c in Category},
    },
    "logging": {"level": "WARNING", "log_to_file": False},
}


def _sr(url: str = "http://t.local/", error: str | None = None) -> ScanResult:
    return ScanResult(
        url=url, status_code=None if error else 200,
        headers={}, body="", elapsed_ms=5.0,
        redirected_url=None, error=error,
    )


def _det(url: str, scores: dict[str, float],
         dominant: str | None = None) -> DetectionResult:
    cats = {c.value: 0.0 for c in Category}
    cats.update(scores)
    comp = max(cats.values())
    dom = dominant or (max(cats, key=lambda k: cats[k]) if comp > 0 else None)
    return DetectionResult(
        url=url, category_scores=cats, composite_score=comp,
        dominant_category=dom, matched_patterns=[], scan_result=_sr(url),
    )


def _ana(
    url: str = "http://t.local/",
    missing: list[str] | None = None,
    insecure: dict[str, str] | None = None,
    forms: list[FormInfo] | None = None,
    js_hits: list[str] | None = None,
    kw_found: list[str] | None = None,
) -> AnalysisResult:
    return AnalysisResult(
        url=url, status_code=200,
        title=TitleInfo(raw="", lower=""),
        forms=forms or [],
        headers=HeaderAudit(
            present={},
            missing=missing or [],
            insecure_values=insecure or {},
        ),
        scripts=ScriptInfo(total_inline_scripts=0,
                           suspicious_pattern_hits=js_hits or []),
        keywords=KeywordInfo(found=kw_found or [], snippet_map={}),
    )


def _login_form(suspicious_action: bool = True) -> FormInfo:
    return FormInfo(
        action="/admin/login" if suspicious_action else "/submit",
        method="POST",
        has_password_field=True,
        has_username_field=True,
        has_hidden_fields=False,
        action_is_external=False,
        action_path_suspicious=suspicious_action,
        fields=[
            FormField(tag="input", name="password", field_type="password",
                      value="", is_hidden=False, is_password=True,
                      is_sensitive_name=True),
        ],
    )


def _scorer() -> Scorer:
    return Scorer(BASE_CONFIG)


# ─── ScoringConfig / _parse_config ────────────────────────────────────────────

def test_parse_config_reads_threshold():
    cfg = _parse_config(BASE_CONFIG)
    assert cfg.initial_threshold == 0.70


def test_parse_config_reads_bounds():
    cfg = _parse_config(BASE_CONFIG)
    assert cfg.min_threshold == 0.50
    assert cfg.max_threshold == 0.82


def test_parse_config_reads_aggregation():
    cfg = _parse_config(BASE_CONFIG)
    assert cfg.aggregation == "max_pool"


def test_parse_config_category_weights():
    cfg = _parse_config(BASE_CONFIG)
    assert cfg.category_weights.get("admin") == 1.0


def test_parse_config_defaults_on_empty():
    cfg = _parse_config({})
    assert cfg.initial_threshold == 0.70
    assert cfg.aggregation == "max_pool"


# ─── _severity ────────────────────────────────────────────────────────────────

def test_severity_critical():
    assert _severity(0.80) == Severity.CRITICAL
    assert _severity(0.75) == Severity.CRITICAL


def test_severity_high():
    assert _severity(0.60) == Severity.HIGH
    assert _severity(0.55) == Severity.HIGH


def test_severity_medium():
    assert _severity(0.40) == Severity.MEDIUM
    assert _severity(0.35) == Severity.MEDIUM


def test_severity_low():
    assert _severity(0.15) == Severity.LOW
    assert _severity(0.10) == Severity.LOW


def test_severity_none():
    assert _severity(0.09) == Severity.NONE
    assert _severity(0.00) == Severity.NONE


def test_severity_bands_are_descending():
    thresholds = [t for t, _ in _SEVERITY_BANDS]
    assert thresholds == sorted(thresholds, reverse=True)


# ─── _confidence ──────────────────────────────────────────────────────────────

def test_confidence_at_threshold_is_half():
    assert _confidence(0.70, 0.70) == pytest.approx(0.5, abs=0.001)


def test_confidence_well_above_threshold_is_high():
    assert _confidence(0.95, 0.70) > 0.85


def test_confidence_well_below_threshold_is_low():
    assert _confidence(0.10, 0.70) < 0.10


def test_confidence_in_unit_interval():
    for v in [0.0, 0.3, 0.5, 0.7, 0.9, 1.0]:
        c = _confidence(v, 0.70)
        assert 0.0 <= c <= 1.0


def test_confidence_monotone_increasing():
    scores = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
    confs = [_confidence(s, 0.70) for s in scores]
    assert confs == sorted(confs)


# ─── Scorer.score — core behaviour ────────────────────────────────────────────

def test_score_returns_scoring_result():
    s = _scorer()
    r = s.score(_det("http://t.local/", {}), _ana())
    assert isinstance(r, ScoringResult)


def test_score_url_preserved():
    s = _scorer()
    r = s.score(_det("http://t.local/admin/", {"admin": 0.50}), _ana("http://t.local/admin/"))
    assert r.url == "http://t.local/admin/"


def test_score_zero_detection_no_bonus_gives_none_severity():
    s = _scorer()
    r = s.score(_det("http://t.local/", {}), _ana())
    assert r.severity == Severity.NONE
    assert r.label == Label.BENIGN


def test_score_high_detection_gives_vulnerable():
    s = _scorer()
    r = s.score(_det("http://t.local/wp-admin/", {"admin": 0.85}), _ana())
    assert r.label == Label.VULNERABLE
    assert r.composite_score >= 0.70


def test_score_composite_equals_max_category():
    s = _scorer()
    scores = {"admin": 0.60, "sqli": 0.30, "login": 0.10}
    r = s.score(_det("http://t.local/", scores), _ana())
    assert r.composite_score >= 0.60


def test_score_composite_bounded_to_one():
    s = _scorer()
    r = s.score(_det("http://t.local/", {"admin": 1.0, "sqli": 1.0}), _ana())
    assert r.composite_score <= 1.0


def test_score_all_categories_present():
    s = _scorer()
    r = s.score(_det("http://t.local/", {}), _ana())
    for cat in Category:
        assert cat.value in r.category_scores


def test_score_threshold_used_matches_initial():
    s = _scorer()
    r = s.score(_det("http://t.local/", {}), _ana())
    assert r.threshold_used == pytest.approx(0.70)


def test_score_detection_result_passed_through():
    s = _scorer()
    det = _det("http://t.local/", {"admin": 0.40})
    r = s.score(det, _ana())
    assert r.detection_result is det


def test_score_analysis_result_passed_through():
    s = _scorer()
    ana = _ana()
    r = s.score(_det("http://t.local/", {}), ana)
    assert r.analysis_result is ana


# ─── Severity classification ──────────────────────────────────────────────────

def test_score_critical_severity():
    s = _scorer()
    r = s.score(_det("http://t.local/", {"admin": 0.90}), _ana())
    assert r.severity == Severity.CRITICAL


def test_score_high_severity():
    s = _scorer()
    r = s.score(_det("http://t.local/", {"sqli": 0.60}), _ana())
    assert r.severity == Severity.HIGH


def test_score_medium_severity():
    s = _scorer()
    r = s.score(_det("http://t.local/", {"login": 0.40}), _ana())
    assert r.severity == Severity.MEDIUM


def test_score_low_severity():
    s = _scorer()
    r = s.score(_det("http://t.local/", {"dir_listing": 0.12}), _ana())
    assert r.severity == Severity.LOW


# ─── Analyser bonuses ─────────────────────────────────────────────────────────

def test_header_bonus_applied_to_dominant_category():
    s = _scorer()
    # No detection, 4 missing headers → header bonus flows to admin (default)
    r = s.score(
        _det("http://t.local/", {}),
        _ana(missing=["csp", "xfo", "sts", "xcto"]),
    )
    assert r.analyser_bonuses.get("admin", 0.0) > 0.0


def test_header_bonus_raises_composite():
    s = _scorer()
    base  = s.score(_det("http://t.local/", {}), _ana()).composite_score
    bonus = s.score(_det("http://t.local/", {}),
                    _ana(missing=["csp", "xfo", "sts", "xcto"])).composite_score
    assert bonus > base


def test_insecure_header_adds_bonus():
    s = _scorer()
    r = s.score(
        _det("http://t.local/", {}),
        _ana(insecure={"content-security-policy": "unsafe-inline present"}),
    )
    assert r.analyser_bonuses.get("admin", 0.0) > 0.0


def test_password_form_on_suspicious_action_adds_login_bonus():
    s = _scorer()
    r = s.score(
        _det("http://t.local/", {}),
        _ana(forms=[_login_form(suspicious_action=True)]),
    )
    assert r.analyser_bonuses.get("login", 0.0) > 0.0


def test_password_form_on_normal_action_no_login_bonus():
    s = _scorer()
    r = s.score(
        _det("http://t.local/", {}),
        _ana(forms=[_login_form(suspicious_action=False)]),
    )
    assert r.analyser_bonuses.get("login", 0.0) == 0.0


def test_js_patterns_add_xss_bonus():
    s = _scorer()
    r = s.score(
        _det("http://t.local/", {}),
        _ana(js_hits=["eval\\s*\\(", "innerHTML\\s*="]),
    )
    assert r.analyser_bonuses.get("xss", 0.0) > 0.0


def test_keyword_bonus_applied_to_dominant():
    s = _scorer()
    r = s.score(
        _det("http://t.local/", {"sqli": 0.15}, dominant="sqli"),
        _ana(kw_found=["sql", "error", "debug"]),
    )
    assert r.analyser_bonuses.get("sqli", 0.0) > 0.0


def test_bonus_does_not_exceed_one():
    s = _scorer()
    # Stack every bonus source
    r = s.score(
        _det("http://t.local/", {"admin": 0.95}),
        _ana(
            missing=["csp", "xfo", "sts", "xcto"],
            insecure={"csp": "unsafe"},
            forms=[_login_form()],
            js_hits=["eval", "innerHTML"],
            kw_found=["sql", "error", "debug"],
        ),
    )
    assert r.composite_score <= 1.0
    for v in r.category_scores.values():
        assert v <= 1.0


# ─── Aggregation modes ────────────────────────────────────────────────────────

def test_max_pool_aggregation():
    s = _scorer()
    scores = {"admin": 0.70, "sqli": 0.30}
    r = s.score(_det("http://t.local/", scores), _ana())
    assert r.composite_score >= 0.70


def test_weighted_avg_aggregation_lower_than_max():
    cfg = {**BASE_CONFIG, "scoring": {**BASE_CONFIG["scoring"], "aggregation": "weighted_avg"}}
    s = Scorer(cfg)
    scores = {"admin": 0.80, "sqli": 0.0, "login": 0.0,
              "dir_listing": 0.0, "xss": 0.0, "sensitive": 0.0}
    r = s.score(_det("http://t.local/", scores), _ana())
    # avg of 6 cats where only admin=0.80 → 0.8/6 ≈ 0.133
    assert r.composite_score < 0.80


# ─── Category weight override ─────────────────────────────────────────────────

def test_category_weight_zero_suppresses_score():
    cfg = {
        **BASE_CONFIG,
        "detection": {"category_weights": {c.value: (0.0 if c.value == "admin" else 1.0)
                                            for c in Category}},
    }
    s = Scorer(cfg)
    r = s.score(_det("http://t.local/wp-admin/", {"admin": 0.90}), _ana())
    assert r.category_scores["admin"] == 0.0


def test_category_weight_scales_score():
    cfg_half = {**BASE_CONFIG,
                "detection": {"category_weights": {c.value: (0.5 if c.value == "sqli" else 1.0)
                                                    for c in Category}}}
    s_half = Scorer(cfg_half)
    s_full = _scorer()
    det = _det("http://t.local/", {"sqli": 0.80})
    r_half = s_half.score(det, _ana())
    r_full = s_full.score(det, _ana())
    assert r_half.category_scores["sqli"] < r_full.category_scores["sqli"]


# ─── Dominant category ────────────────────────────────────────────────────────

def test_dominant_category_is_highest_scorer():
    s = _scorer()
    r = s.score(_det("http://t.local/", {"admin": 0.20, "sqli": 0.60}), _ana())
    assert r.dominant_category == "sqli"


def test_dominant_category_none_on_all_zero():
    s = _scorer()
    r = s.score(_det("http://t.local/", {}), _ana())
    assert r.dominant_category is None


# ─── Threshold / update_threshold ─────────────────────────────────────────────

def test_initial_threshold():
    s = _scorer()
    assert s.threshold == pytest.approx(0.70)


def test_update_threshold_raises_on_high_fpr():
    s = _scorer()
    new_t = s.update_threshold(observed_fpr=0.30, observed_accuracy=0.80)
    assert new_t > 0.70


def test_update_threshold_lowers_on_low_accuracy():
    s = _scorer()
    new_t = s.update_threshold(observed_fpr=0.10, observed_accuracy=0.50)
    assert new_t < 0.70


def test_update_threshold_unchanged_when_targets_met():
    s = _scorer()
    new_t = s.update_threshold(observed_fpr=0.10, observed_accuracy=0.80)
    assert new_t == pytest.approx(0.70)


def test_update_threshold_respects_max_bound():
    s = _scorer()
    for _ in range(50):  # force many raises
        s.update_threshold(observed_fpr=1.0, observed_accuracy=1.0)
    assert s.threshold <= 0.82


def test_update_threshold_respects_min_bound():
    s = _scorer()
    for _ in range(50):  # force many lowers
        s.update_threshold(observed_fpr=0.0, observed_accuracy=0.0)
    assert s.threshold >= 0.50


def test_score_uses_updated_threshold():
    s = _scorer()
    s.update_threshold(observed_fpr=0.30, observed_accuracy=0.80)  # raises threshold
    r = s.score(_det("http://t.local/", {"admin": 0.72}), _ana())
    # 0.72 was above 0.70 (old) — after raise to 0.71 it may still be above; after many raises, below
    assert r.threshold_used == pytest.approx(s.threshold)


# ─── score_many ───────────────────────────────────────────────────────────────

def test_score_many_returns_correct_length():
    s = _scorer()
    pairs = [
        (_det(f"http://t.local/p{i}", {}), _ana(f"http://t.local/p{i}"))
        for i in range(5)
    ]
    results = s.score_many(pairs)
    assert len(results) == 5


def test_score_many_preserves_order():
    s = _scorer()
    urls = [f"http://t.local/page{i}" for i in range(4)]
    pairs = [(_det(u, {}), _ana(u)) for u in urls]
    results = s.score_many(pairs)
    assert [r.url for r in results] == urls


def test_score_many_empty_input():
    s = _scorer()
    assert s.score_many([]) == []


# ─── Integration-style: realistic scan scenarios ──────────────────────────────

def test_wp_admin_detected_and_classified():
    """wp-admin URL with admin panel body → VULNERABLE, HIGH or CRITICAL."""
    s = _scorer()
    r = s.score(
        _det("http://t.local/wp-admin/", {"admin": 0.80}),
        _ana("http://t.local/wp-admin/",
             missing=["content-security-policy", "x-frame-options"]),
    )
    assert r.label == Label.VULNERABLE
    assert r.severity in (Severity.HIGH, Severity.CRITICAL)


def test_clean_homepage_not_flagged():
    """Homepage with no signals → BENIGN, NONE severity."""
    s = _scorer()
    r = s.score(_det("http://t.local/", {}), _ana())
    assert r.label == Label.BENIGN
    assert r.severity == Severity.NONE


def test_directory_listing_classified():
    """Dir listing detection score → at least LOW severity."""
    s = _scorer()
    r = s.score(
        _det("http://t.local/files/", {"dir_listing": 0.15}),
        _ana(),
    )
    assert r.severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


def test_sqli_error_page_classified():
    """SQL error page detection → scored and not NONE."""
    s = _scorer()
    r = s.score(
        _det("http://t.local/item?id=1", {"sqli": 0.20}),
        _ana(kw_found=["sql", "error"]),
    )
    assert r.severity != Severity.NONE


def test_confidence_reflects_label():
    """VULNERABLE results have confidence > 0.5; BENIGN results have < 0.5."""
    s = _scorer()
    r_vuln  = s.score(_det("http://t.local/", {"admin": 0.90}), _ana())
    r_benign = s.score(_det("http://t.local/", {}), _ana())
    assert r_vuln.confidence > 0.5
    assert r_benign.confidence < 0.5
