"""
tests/test_payload_tester.py
────────────────────────────
Unit tests for core/payload_tester.py.

All tests use mock Scanner responses — no real HTTP traffic.

Run with:  pytest tests/test_payload_tester.py -v
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from core.payload_tester import (
    PayloadTester,
    PayloadResult,
    UrlTestSummary,
    Payload,
    PayloadConfig,
    load_payloads,
    extract_query_params,
    inject_payload,
    compare_responses,
    _LENGTH_CHANGE_THRESHOLD,
    _SQL_ERROR_PATTERNS,
)
from core.scanner import ScanResult


# ─── Fixtures ─────────────────────────────────────────────────────────────────

BASE_CONFIG = {
    "payloads": {
        "enabled":           True,
        "sqli_payload_file": "payloads/sqli.txt",
        "xss_payload_file":  "payloads/xss.txt",
        "compare_baseline":  True,
    },
    "logging": {"level": "WARNING", "log_to_file": False},
    "scanner": {
        "user_agent": "HybriScan-Test/1.0", "timeout": 5,
        "max_retries": 0, "retry_backoff": 1.0,
        "concurrency": 2, "follow_redirects": True,
        "max_redirects": 3, "verify_ssl": False,
    },
}

DISABLED_CONFIG = {
    **BASE_CONFIG,
    "payloads": {**BASE_CONFIG["payloads"], "enabled": False},
}


def _sr(url: str = "http://t.local/", body: str = "<html>ok</html>",
        status: int = 200, error: str | None = None) -> ScanResult:
    return ScanResult(
        url=url, status_code=None if error else status,
        headers={}, body=body, elapsed_ms=5.0,
        redirected_url=None, error=error,
    )


def _mock_scanner(side_effects: list[ScanResult]) -> MagicMock:
    scanner = MagicMock()
    scanner.get = AsyncMock(side_effect=side_effects)
    return scanner


def _tester(config: dict = BASE_CONFIG) -> PayloadTester:
    return PayloadTester(config)


# ─── load_payloads ────────────────────────────────────────────────────────────

def test_load_payloads_from_real_file():
    payloads = load_payloads("payloads/sqli.txt", "sqli")
    assert len(payloads) > 0
    assert all(p.category == "sqli" for p in payloads)


def test_load_payloads_skips_comments():
    payloads = load_payloads("payloads/sqli.txt", "sqli")
    assert not any(p.value.startswith("#") for p in payloads)


def test_load_payloads_skips_blank_lines():
    payloads = load_payloads("payloads/sqli.txt", "sqli")
    assert not any(p.value == "" for p in payloads)


def test_load_payloads_missing_file_returns_empty():
    result = load_payloads("payloads/nonexistent.txt", "sqli")
    assert result == []


def test_load_xss_payloads():
    payloads = load_payloads("payloads/xss.txt", "xss")
    assert len(payloads) > 0
    assert all(p.category == "xss" for p in payloads)


def test_load_payloads_category_assigned(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("payload1\npayload2\n")
    payloads = load_payloads(str(f), "xss")
    assert all(p.category == "xss" for p in payloads)
    assert [p.value for p in payloads] == ["payload1", "payload2"]


# ─── extract_query_params ─────────────────────────────────────────────────────

def test_extract_single_param():
    assert extract_query_params("http://t.local/page?id=1") == ["id"]


def test_extract_multiple_params():
    params = extract_query_params("http://t.local/search?q=test&page=1&sort=asc")
    assert set(params) == {"q", "page", "sort"}


def test_extract_no_params():
    assert extract_query_params("http://t.local/page") == []


def test_extract_empty_param_value():
    params = extract_query_params("http://t.local/page?id=&name=")
    assert "id" in params
    assert "name" in params


def test_extract_ignores_fragment():
    params = extract_query_params("http://t.local/page?id=1#section")
    assert params == ["id"]


# ─── inject_payload ───────────────────────────────────────────────────────────

def test_inject_replaces_target_param():
    url = inject_payload("http://t.local/page?id=1", "id", "'")
    assert "id=%27" in url or "id='" in url  # URL-encoded or raw


def test_inject_preserves_other_params():
    url = inject_payload("http://t.local/search?q=test&page=1", "q", "<hss>")
    assert "page=1" in url


def test_inject_on_url_with_no_params():
    # No params — inject creates the parameter
    url = inject_payload("http://t.local/page", "id", "1")
    assert "id=1" in url


def test_inject_uses_payload_value():
    payload = "1 OR 1=1"
    url = inject_payload("http://t.local/item?id=5", "id", payload)
    assert "id=" in url
    assert "OR" in url or "1+OR+1%3D1" in url or "1%20OR" in url


def test_inject_different_params():
    base = "http://t.local/p?a=1&b=2"
    url_a = inject_payload(base, "a", "X")
    url_b = inject_payload(base, "b", "X")
    assert url_a != url_b


# ─── compare_responses ────────────────────────────────────────────────────────

def test_compare_status_change_detected():
    b = _sr(status=200, body="hello")
    p = _sr(status=500, body="hello")
    cmp = compare_responses(b, p, Payload("sqli", "'"))
    assert cmp["status_changed"] is True


def test_compare_no_status_change():
    b = _sr(status=200, body="hello")
    p = _sr(status=200, body="hello")
    cmp = compare_responses(b, p, Payload("sqli", "'"))
    assert cmp["status_changed"] is False


def test_compare_length_change_above_threshold():
    b = _sr(body="A" * 200)
    p = _sr(body="A" * 400)   # 100% increase
    cmp = compare_responses(b, p, Payload("sqli", "'"))
    assert cmp["length_changed"] is True
    assert cmp["length_delta_pct"] > _LENGTH_CHANGE_THRESHOLD


def test_compare_length_change_below_threshold():
    b = _sr(body="A" * 1000)
    p = _sr(body="A" * 1001)   # 0.1% — under threshold
    cmp = compare_responses(b, p, Payload("sqli", "'"))
    assert cmp["length_changed"] is False


def test_compare_sql_error_detected():
    p_body = "You have an error in your SQL syntax near 'WHERE'"
    b = _sr(body="ok")
    p = _sr(body=p_body)
    cmp = compare_responses(b, p, Payload("sqli", "'"))
    assert cmp["sql_error_found"] is True


def test_compare_no_sql_error_on_clean():
    b = _sr(body="<html>results</html>")
    p = _sr(body="<html>results for query</html>")
    cmp = compare_responses(b, p, Payload("sqli", "'"))
    assert cmp["sql_error_found"] is False


def test_compare_reflection_detected():
    payload = Payload("xss", "<hss>")
    b = _sr(body="<html>search results</html>")
    p = _sr(body="<html>search results for <hss></html>")
    cmp = compare_responses(b, p, payload)
    assert cmp["reflection_found"] is True


def test_compare_no_reflection_on_clean():
    payload = Payload("xss", "<hss>")
    b = _sr(body="<html>results</html>")
    p = _sr(body="<html>results</html>")
    cmp = compare_responses(b, p, payload)
    assert cmp["reflection_found"] is False


def test_compare_zero_baseline_length():
    b = _sr(body="")
    p = _sr(body="something appeared")
    cmp = compare_responses(b, p, Payload("sqli", "'"))
    assert cmp["length_delta_pct"] == 1.0
    assert cmp["length_changed"] is True


def test_compare_returns_all_keys():
    b = _sr(body="hello")
    p = _sr(body="hello")
    cmp = compare_responses(b, p, Payload("sqli", "'"))
    for key in ("status_changed", "length_delta_pct", "length_changed",
                "sql_error_found", "reflection_found"):
        assert key in cmp


# ─── SQL error patterns ───────────────────────────────────────────────────────

def test_sql_pattern_mysql_syntax():
    assert any(p.search("you have an error in your sql syntax near '1'")
               for p in _SQL_ERROR_PATTERNS)


def test_sql_pattern_ora_error():
    assert any(p.search("ORA-00933: SQL command not properly ended")
               for p in _SQL_ERROR_PATTERNS)


def test_sql_pattern_php_mysql_warning():
    assert any(p.search("Warning: mysql_fetch_array() expects parameter 1")
               for p in _SQL_ERROR_PATTERNS)


def test_sql_pattern_no_false_positive():
    assert not any(p.search("Welcome to our website. Please log in.")
                   for p in _SQL_ERROR_PATTERNS)


# ─── PayloadTester properties ─────────────────────────────────────────────────

def test_tester_enabled():
    t = _tester(BASE_CONFIG)
    assert t.enabled is True


def test_tester_disabled():
    t = _tester(DISABLED_CONFIG)
    assert t.enabled is False


def test_tester_payloads_loaded():
    t = _tester()
    assert len(t.payloads) > 0


def test_tester_payloads_include_both_categories():
    t = _tester()
    cats = {p.category for p in t.payloads}
    assert "sqli" in cats
    assert "xss" in cats


# ─── PayloadTester.test_url ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_test_url_disabled_returns_empty():
    t = _tester(DISABLED_CONFIG)
    scanner = _mock_scanner([])
    result = await t.test_url(scanner, "http://t.local/page?id=1")
    assert result.total_probes == 0
    assert result.anomalies == []


@pytest.mark.asyncio
async def test_test_url_no_params_returns_empty():
    t = _tester()
    scanner = _mock_scanner([])
    result = await t.test_url(scanner, "http://t.local/page")
    assert result.parameters_tested == []
    assert result.total_probes == 0


@pytest.mark.asyncio
async def test_test_url_fetches_baseline_when_none():
    t = _tester()
    baseline = _sr("http://t.local/page?id=1", body="ok")
    # baseline + one probe per payload
    n_payloads = len(t.payloads)
    responses = [baseline] + [_sr(body="ok")] * n_payloads
    scanner = _mock_scanner(responses)
    result = await t.test_url(scanner, "http://t.local/page?id=1")
    assert result.total_probes == n_payloads


@pytest.mark.asyncio
async def test_test_url_uses_provided_baseline():
    t = _tester()
    baseline = _sr("http://t.local/page?id=1", body="baseline body")
    n_payloads = len(t.payloads)
    # No baseline fetch needed — only probe responses
    responses = [_sr(body="response")] * n_payloads
    scanner = _mock_scanner(responses)
    result = await t.test_url(scanner, "http://t.local/page?id=1",
                               baseline=baseline)
    assert result.total_probes == n_payloads


@pytest.mark.asyncio
async def test_test_url_detects_sql_error_anomaly():
    t = _tester()
    baseline = _sr(body="<html>results</html>")
    sql_body = "You have an error in your SQL syntax near '1'"
    # All probes return sql_body to guarantee at least one hit
    n = len(t.payloads)
    responses = [_sr(body=sql_body)] * n
    scanner = _mock_scanner(responses)
    result = await t.test_url(scanner, "http://t.local/item?id=1",
                               baseline=baseline)
    assert result.sql_error_count > 0
    assert len(result.anomalies) > 0


@pytest.mark.asyncio
async def test_test_url_detects_reflection_anomaly():
    t = _tester()
    # Find first XSS payload to build a reflecting response
    xss_payload = next(p for p in t.payloads if p.category == "xss")
    baseline = _sr(body="<html>search</html>")

    def _make_response(call_idx: list[int]) -> ScanResult:
        call_idx[0] += 1
        return _sr(body=f"<html>results {xss_payload.value}</html>")

    n = len(t.payloads)
    responses = [_sr(body=f"reflect {p.value}") for p in t.payloads]
    scanner = _mock_scanner(responses)
    result = await t.test_url(scanner, "http://t.local/search?q=test",
                               baseline=baseline)
    assert result.reflection_count > 0


@pytest.mark.asyncio
async def test_test_url_no_anomaly_on_stable_responses():
    t = _tester()
    stable_body = "<html>stable page content here</html>"
    baseline = _sr(body=stable_body)
    n = len(t.payloads)
    responses = [_sr(body=stable_body)] * n
    scanner = _mock_scanner(responses)
    result = await t.test_url(scanner, "http://t.local/page?id=1",
                               baseline=baseline)
    assert result.sql_error_count == 0
    assert result.reflection_count == 0


@pytest.mark.asyncio
async def test_test_url_aborts_on_baseline_failure():
    t = _tester()
    failed_baseline = _sr(error="ConnectionRefused")
    scanner = _mock_scanner([failed_baseline])
    result = await t.test_url(scanner, "http://t.local/page?id=1")
    assert result.total_probes == 0


@pytest.mark.asyncio
async def test_test_url_summary_url_matches():
    t = _tester()
    url = "http://t.local/search?q=test"
    n = len(t.payloads)
    responses = [_sr(body="ok")] * (n + 1)   # +1 for baseline fetch
    scanner = _mock_scanner(responses)
    result = await t.test_url(scanner, url)
    assert result.url == url


@pytest.mark.asyncio
async def test_test_url_parameters_tested_populated():
    t = _tester()
    url = "http://t.local/search?q=hello&page=1"
    n_params = 2
    n_payloads = len(t.payloads)
    # baseline + (n_params * n_payloads) probes
    responses = [_sr(body="ok")] * (1 + n_params * n_payloads)
    scanner = _mock_scanner(responses)
    result = await t.test_url(scanner, url)
    assert set(result.parameters_tested) == {"q", "page"}
    assert result.total_probes == n_params * n_payloads


# ─── PayloadTester.test_many ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_test_many_returns_correct_length():
    t = _tester()
    urls = ["http://t.local/a", "http://t.local/b?id=1"]
    n = len(t.payloads)
    # url[0] has no params; url[1]: baseline + n probes
    responses = [_sr(body="ok")] * (1 + n)
    scanner = _mock_scanner(responses)
    results = await t.test_many(scanner, urls)
    assert len(results) == 2


@pytest.mark.asyncio
async def test_test_many_preserves_url_order():
    t = _tester()
    urls = ["http://t.local/a", "http://t.local/b"]
    scanner = _mock_scanner([])  # no params → no fetches
    results = await t.test_many(scanner, urls)
    assert [r.url for r in results] == urls


@pytest.mark.asyncio
async def test_test_many_empty_list():
    t = _tester()
    scanner = _mock_scanner([])
    results = await t.test_many(scanner, [])
    assert results == []


# ─── _is_anomaly ──────────────────────────────────────────────────────────────

def _make_pr(**kwargs) -> PayloadResult:
    defaults = dict(
        url="http://t.local/", parameter="id",
        payload=Payload("sqli", "'"),
        baseline_status=200, payload_status=200,
        status_changed=False, baseline_length=100,
        payload_length=100, length_delta_pct=0.0,
        length_changed=False, sql_error_found=False,
        reflection_found=False, error=None,
    )
    defaults.update(kwargs)
    return PayloadResult(**defaults)


def test_is_anomaly_sql_error():
    t = _tester()
    assert t._is_anomaly(_make_pr(sql_error_found=True))


def test_is_anomaly_reflection():
    t = _tester()
    assert t._is_anomaly(_make_pr(reflection_found=True))


def test_is_anomaly_status_change():
    t = _tester()
    assert t._is_anomaly(_make_pr(status_changed=True))


def test_is_anomaly_length_change():
    t = _tester()
    assert t._is_anomaly(_make_pr(length_changed=True))


def test_not_anomaly_on_stable():
    t = _tester()
    assert not t._is_anomaly(_make_pr())
