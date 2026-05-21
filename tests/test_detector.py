"""
tests/test_detector.py
──────────────────────
Unit tests for core/detector.py.

Covers:
  - Pattern bank weight and compilation integrity
  - Per-category detection with synthetic HTML bodies (mirrors paper's
    dataset construction in Section VII-A)
  - Hard-negative discrimination (benign pages with security keywords)
  - Failed ScanResult produces zero-score result
  - analyse_many() batch operation
  - Category multiplier from config

Run with:  pytest tests/test_detector.py -v
"""

import pytest

from core.detector import (
    Detector,
    DetectionResult,
    PatternMatch,
    Category,
    ADMIN_PATTERNS,
    SQLI_PATTERNS,
    LOGIN_PATTERNS,
    DIR_LISTING_PATTERNS,
    XSS_PATTERNS,
    SENSITIVE_PATTERNS,
    _BANKS,
    _MAX_SCORES,
)
from core.scanner import ScanResult


# ─── Fixtures ─────────────────────────────────────────────────────────────────

BASE_CONFIG = {
    "detection": {
        "category_weights": {
            "admin": 1.0, "sqli": 1.0, "login": 1.0,
            "dir_listing": 1.0, "xss": 1.0, "sensitive": 1.0,
        }
    },
    "logging": {"level": "WARNING", "log_to_file": False},
}


def _result(url: str, body: str = "", status: int = 200,
            error: str | None = None) -> ScanResult:
    return ScanResult(
        url=url,
        status_code=status if not error else None,
        headers={},
        body=body,
        elapsed_ms=5.0,
        redirected_url=None,
        error=error,
    )


def det() -> Detector:
    return Detector(BASE_CONFIG)


# ─── Pattern Bank Integrity ───────────────────────────────────────────────────

def test_all_patterns_have_valid_weights():
    for cat, bank in _BANKS.items():
        for p in bank:
            assert 0.0 < p.weight <= 1.0, \
                f"{cat.value}: pattern '{p.description}' has invalid weight {p.weight}"


def test_all_patterns_compile():
    """Patterns are compiled at import time — confirm no re.error occurred."""
    import re
    for cat, bank in _BANKS.items():
        for p in bank:
            assert isinstance(p.regex, re.Pattern), \
                f"{cat.value}: '{p.description}' is not a compiled pattern"


def test_max_scores_match_sum_of_weights():
    for cat, bank in _BANKS.items():
        expected = sum(p.weight for p in bank)
        assert abs(_MAX_SCORES[cat] - expected) < 1e-9, \
            f"{cat.value}: max_score mismatch"


def test_all_six_categories_registered():
    assert set(_BANKS.keys()) == set(Category)


def test_pattern_descriptions_are_non_empty():
    for cat, bank in _BANKS.items():
        for p in bank:
            assert p.description.strip(), \
                f"{cat.value}: empty description for pattern"


# ─── Admin Detection ──────────────────────────────────────────────────────────

def test_admin_detects_wp_admin_url():
    r = _result("http://target.local/wp-admin/", "<html><body>Admin</body></html>")
    dr = det().analyse(r)
    assert dr.category_scores["admin"] > 0.0


def test_admin_detects_phpmyadmin_url():
    r = _result("http://target.local/phpmyadmin/")
    dr = det().analyse(r)
    assert dr.category_scores["admin"] > 0.05


def test_admin_detects_admin_panel_in_title():
    body = "<html><head><title>Administration Panel</title></head><body></body></html>"
    r = _result("http://target.local/dashboard", body)
    dr = det().analyse(r)
    assert dr.category_scores["admin"] > 0.0


def test_admin_detects_generic_admin_path():
    r = _result("http://target.local/admin/", "")
    dr = det().analyse(r)
    assert dr.category_scores["admin"] > 0.0


def test_admin_score_normalised_to_one_or_less():
    body = " ".join([
        "admin administrator /wp-admin /administrator /phpmyadmin",
        "<title>Admin Panel</title>",
        "admin panel dashboard logout control panel",
    ])
    r = _result("http://target.local/wp-admin/", body)
    dr = det().analyse(r)
    assert 0.0 <= dr.category_scores["admin"] <= 1.0


# ─── SQL Injection Detection ──────────────────────────────────────────────────

def test_sqli_detects_mysql_syntax_error():
    body = "You have an error in your SQL syntax near 'WHERE id='"
    r = _result("http://target.local/item?id=1", body)
    dr = det().analyse(r)
    assert dr.category_scores["sqli"] > 0.05


def test_sqli_detects_oracle_ora_error():
    body = "ORA-00933: SQL command not properly ended"
    r = _result("http://target.local/search?q=test", body)
    dr = det().analyse(r)
    assert dr.category_scores["sqli"] > 0.05


def test_sqli_detects_union_select_in_url():
    r = _result("http://target.local/api?id=1+UNION+SELECT+1,2,3", "")
    dr = det().analyse(r)
    assert dr.category_scores["sqli"] > 0.05


def test_sqli_detects_php_mysql_warning():
    body = "Warning: mysql_fetch_array() expects parameter 1"
    r = _result("http://target.local/page", body)
    dr = det().analyse(r)
    assert dr.category_scores["sqli"] > 0.05


def test_sqli_no_false_positive_on_clean_page():
    body = "<html><body><p>Welcome to our store.</p></body></html>"
    r = _result("http://target.local/", body)
    dr = det().analyse(r)
    assert dr.category_scores["sqli"] == 0.0


# ─── Login Detection ──────────────────────────────────────────────────────────

def test_login_detects_password_input():
    body = '<form><input type="password" name="password"><input name="username"></form>'
    r = _result("http://target.local/login", body)
    dr = det().analyse(r)
    assert dr.category_scores["login"] > 0.15


def test_login_detects_login_url():
    r = _result("http://target.local/signin", "")
    dr = det().analyse(r)
    assert dr.category_scores["login"] > 0.05


def test_login_detects_wp_login_php():
    r = _result("http://target.local/wp-login.php", "")
    dr = det().analyse(r)
    assert dr.category_scores["login"] > 0.05


def test_login_detects_title_keyword():
    body = "<html><head><title>Login to your account</title></head></html>"
    r = _result("http://target.local/auth", body)
    dr = det().analyse(r)
    assert dr.category_scores["login"] > 0.0


def test_login_no_false_positive_on_home_page():
    body = "<html><body><h1>Welcome</h1><p>Our products.</p></body></html>"
    r = _result("http://target.local/", body)
    dr = det().analyse(r)
    assert dr.category_scores["login"] == 0.0


# ─── Directory Listing Detection ──────────────────────────────────────────────

def test_dir_listing_detects_index_of_in_title():
    body = "<html><head><title>Index of /var/www</title></head><body></body></html>"
    r = _result("http://target.local/files/", body)
    dr = det().analyse(r)
    assert dr.category_scores["dir_listing"] > 0.10


def test_dir_listing_detects_parent_directory_link():
    body = '<html><body><a href="..">Parent Directory</a><hr></body></html>'
    r = _result("http://target.local/uploads/", body)
    dr = det().analyse(r)
    assert dr.category_scores["dir_listing"] > 0.10


def test_dir_listing_detects_column_headers():
    body = "Last modified&nbsp;&nbsp;Size&nbsp;&nbsp;Description"
    r = _result("http://target.local/static/", body)
    dr = det().analyse(r)
    assert dr.category_scores["dir_listing"] > 0.0


def test_dir_listing_no_false_positive_on_clean():
    body = "<html><body><p>404 - Page Not Found</p></body></html>"
    r = _result("http://target.local/notexist", body)
    dr = det().analyse(r)
    assert dr.category_scores["dir_listing"] == 0.0


# ─── XSS Detection ────────────────────────────────────────────────────────────

def test_xss_detects_html_tag_in_query_param():
    r = _result("http://target.local/search?q=<script>", "")
    dr = det().analyse(r)
    assert dr.category_scores["xss"] > 0.0


def test_xss_detects_event_handler_in_param():
    r = _result("http://target.local/page?name=test&cb=onerror=alert(1)", "")
    dr = det().analyse(r)
    assert dr.category_scores["xss"] > 0.0


def test_xss_detects_inline_alert_in_body():
    body = "<script>alert('XSS')</script>"
    r = _result("http://target.local/search?q=test", body)
    dr = det().analyse(r)
    assert dr.category_scores["xss"] > 0.0


def test_xss_no_false_positive_on_clean_page():
    body = "<html><body><p>Search results for: shoes</p></body></html>"
    r = _result("http://target.local/search?q=shoes", body)
    dr = det().analyse(r)
    assert dr.category_scores["xss"] == 0.0


# ─── Sensitive File Detection ─────────────────────────────────────────────────

def test_sensitive_detects_env_file():
    r = _result("http://target.local/.env", "APP_KEY=base64:abcdef\nDB_PASSWORD=secret")
    dr = det().analyse(r)
    assert dr.category_scores["sensitive"] > 0.20


def test_sensitive_detects_git_directory():
    r = _result("http://target.local/.git/", "")
    dr = det().analyse(r)
    assert dr.category_scores["sensitive"] > 0.0


def test_sensitive_detects_phpinfo():
    body = "<?php phpinfo() ?>"
    r = _result("http://target.local/phpinfo.php", body)
    dr = det().analyse(r)
    assert dr.category_scores["sensitive"] > 0.10


def test_sensitive_detects_db_password_in_body():
    body = "DB_PASSWORD=hunter2\nDB_USER=root"
    r = _result("http://target.local/config.php", body)
    dr = det().analyse(r)
    assert dr.category_scores["sensitive"] > 0.05


def test_sensitive_no_false_positive_on_about_page():
    body = "<html><body><h1>About Us</h1><p>We build software.</p></body></html>"
    r = _result("http://target.local/about", body)
    dr = det().analyse(r)
    assert dr.category_scores["sensitive"] == 0.0


# ─── Hard-Negative Discrimination (mirrors paper Section VII-A) ───────────────

def test_hard_neg_blog_post_about_admin_security():
    """
    /blog/securing-admin-panels — URL contains 'admin', body discusses
    admin security.  Should produce low composite (not flagged).
    """
    body = (
        "<html><head><title>How to secure your admin panel</title></head>"
        "<body><p>Admin panels should always use two-factor authentication. "
        "This article explains how to harden your admin dashboard.</p></body></html>"
    )
    r = _result("http://target.local/blog/securing-admin-panels", body)
    dr = det().analyse(r)
    # Composite score should be low — no high-weight patterns fire
    assert dr.composite_score < 0.35, (
        f"Hard-negative false positive: composite={dr.composite_score:.4f}"
    )


def test_hard_neg_tutorial_about_sqli():
    body = (
        "<html><body><h1>SQL Injection Tutorial</h1>"
        "<p>SQL injection occurs when user input is not sanitised. "
        "Always use parameterised queries to prevent SQL injection attacks.</p>"
        "</body></html>"
    )
    r = _result("http://target.local/tutorial/sql-injection", body)
    dr = det().analyse(r)
    assert dr.composite_score < 0.35, (
        f"Hard-negative false positive: composite={dr.composite_score:.4f}"
    )


def test_hard_neg_login_systems_article():
    body = (
        "<html><body><h1>How Login Systems Work</h1>"
        "<p>Modern authentication uses bcrypt hashing. "
        "Never store passwords in plaintext.</p></body></html>"
    )
    r = _result("http://target.local/article/login-systems", body)
    dr = det().analyse(r)
    assert dr.composite_score < 0.35


# ─── DetectionResult Structure ────────────────────────────────────────────────

def test_all_categories_present_in_result():
    r = _result("http://target.local/", "<html></html>")
    dr = det().analyse(r)
    for cat in Category:
        assert cat.value in dr.category_scores


def test_composite_is_max_of_category_scores():
    body = '<html><head><title>Index of /</title></head></html>'
    r = _result("http://target.local/files/", body)
    dr = det().analyse(r)
    assert dr.composite_score == max(dr.category_scores.values())


def test_dominant_category_matches_highest_score():
    body = "<title>Index of /var/www</title>"
    r = _result("http://target.local/files/", body)
    dr = det().analyse(r)
    assert dr.dominant_category == max(
        dr.category_scores, key=lambda k: dr.category_scores[k]
    )


def test_matched_patterns_populated_on_detection():
    body = "You have an error in your SQL syntax"
    r = _result("http://target.local/item?id=1", body)
    dr = det().analyse(r)
    assert len(dr.matched_patterns) > 0
    assert all(isinstance(m, PatternMatch) for m in dr.matched_patterns)


def test_zero_score_on_failed_request():
    r = _result("http://target.local/fail", error="ConnectionRefused")
    dr = det().analyse(r)
    assert dr.composite_score == 0.0
    assert dr.dominant_category is None
    assert dr.matched_patterns == []


def test_all_scores_zero_on_clean_html():
    body = "<html><body><p>Hello world.</p></body></html>"
    r = _result("http://target.local/home", body)
    dr = det().analyse(r)
    assert dr.composite_score == 0.0


# ─── analyse_many ─────────────────────────────────────────────────────────────

def test_analyse_many_returns_same_length():
    d = det()
    results = [
        _result("http://t.local/admin/", "admin panel"),
        _result("http://t.local/", "hello"),
        _result("http://t.local/fail", error="timeout"),
    ]
    drs = d.analyse_many(results)
    assert len(drs) == 3


def test_analyse_many_preserves_order():
    d = det()
    urls = [f"http://t.local/page{i}" for i in range(5)]
    results = [_result(u, f"page {i}") for i, u in enumerate(urls)]
    drs = d.analyse_many(results)
    assert [dr.url for dr in drs] == urls


# ─── Category Multiplier ──────────────────────────────────────────────────────

def test_category_multiplier_zero_suppresses_score():
    config = {
        "detection": {"category_weights": {"admin": 0.0, "sqli": 1.0,
                                            "login": 1.0, "dir_listing": 1.0,
                                            "xss": 1.0, "sensitive": 1.0}},
        "logging": {"level": "WARNING", "log_to_file": False},
    }
    d = Detector(config)
    r = _result("http://target.local/wp-admin/", "<title>Administration</title>")
    dr = d.analyse(r)
    assert dr.category_scores["admin"] == 0.0


def test_category_multiplier_applied_correctly():
    config = {
        "detection": {"category_weights": {"admin": 0.5, "sqli": 1.0,
                                            "login": 1.0, "dir_listing": 1.0,
                                            "xss": 1.0, "sensitive": 1.0}},
        "logging": {"level": "WARNING", "log_to_file": False},
    }
    d_half = Detector(config)
    d_full = det()
    r = _result("http://target.local/wp-admin/", "<title>Admin Panel</title>")
    score_half = d_half.analyse(r).category_scores["admin"]
    score_full = d_full.analyse(r).category_scores["admin"]
    assert score_half <= score_full
