"""
tests/test_pipeline.py
──────────────────────
Integration tests for core/pipeline.py and the wired main.py.

Uses mock HTTP responses throughout — no real network traffic.

Run with:  pytest tests/test_pipeline.py -v
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.pipeline import Pipeline, PipelineResult, print_summary
from core.scanner import ScanResult


# ─── Fixtures ─────────────────────────────────────────────────────────────────

BASE_CONFIG = {
    "scanner": {
        "user_agent": "HybriScan-Test/1.0", "timeout": 5,
        "max_retries": 0, "retry_backoff": 1.0,
        "concurrency": 2, "follow_redirects": True,
        "max_redirects": 3, "verify_ssl": False,
    },
    "crawler": {
        "max_depth": 1, "max_pages": 10,
        "respect_robots_txt": False,
        "url_filter_extensions": [".png", ".css", ".js"],
    },
    "detection": {
        "category_weights": {
            "admin": 1.0, "sqli": 1.0, "login": 1.0,
            "dir_listing": 1.0, "xss": 1.0, "sensitive": 1.0,
        }
    },
    "scoring": {
        "initial_threshold": 0.70, "min_threshold": 0.50,
        "max_threshold": 0.82, "target_fpr": 0.15,
        "target_accuracy": 0.75, "max_iterations": 30,
        "aggregation": "max_pool",
    },
    "reporting": {
        "output_dir": "/tmp/hybriscan_test_reports",
        "format": "json",
        "include_score_vectors": True,
        "include_timing": True,
        "verbose": False,
    },
    "payloads": {
        "enabled": False,
        "sqli_payload_file": "payloads/sqli.txt",
        "xss_payload_file":  "payloads/xss.txt",
        "compare_baseline":  True,
    },
    "wordlist": {},
    "logging": {"level": "WARNING", "log_to_file": False},
}

TARGET = "http://target.local"

CLEAN_HTML    = "<html><body><p>Welcome</p></body></html>"
ADMIN_HTML    = "<html><head><title>Administration Panel</title></head><body>admin panel logout</body></html>"
LOGIN_HTML    = '<html><body><form action="/login"><input type="password" name="password"></form></body></html>'
DIR_HTML      = "<html><head><title>Index of /var/www</title></head><body><a href='..'>Parent Directory</a></body></html>"
SQLI_HTML     = "You have an error in your SQL syntax near 'WHERE id='"


def _sr(url: str, body: str = CLEAN_HTML, status: int = 200,
        error: str | None = None) -> ScanResult:
    return ScanResult(
        url=url, status_code=None if error else status,
        headers={}, body=body, elapsed_ms=12.0,
        redirected_url=None, error=error,
    )


def _pipeline(config: dict = BASE_CONFIG, crawl: bool = False) -> Pipeline:
    return Pipeline(config, crawl=crawl)


# ─── Pipeline._wordlist_paths ─────────────────────────────────────────────────

def test_wordlist_fallback_returns_paths():
    p = _pipeline()
    paths = p._wordlist_paths()
    assert len(paths) > 0
    assert "admin" in paths or "wp-admin" in paths


def test_wordlist_loads_from_file(tmp_path):
    wl = tmp_path / "paths.txt"
    wl.write_text("# comment\nadmin\nlogin\n\n")
    cfg = {**BASE_CONFIG, "wordlist": {"admin_paths": str(wl)}}
    p = Pipeline(cfg)
    paths = p._wordlist_paths()
    assert "admin" in paths
    assert "login" in paths
    assert not any(line.startswith("#") for line in paths)


# ─── Pipeline._collect_urls ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_collect_urls_includes_base():
    p = _pipeline()
    # Mock scanner — _collect_urls only calls scanner during crawl
    scanner = MagicMock()
    urls = await p._collect_urls(scanner, TARGET)
    assert TARGET in urls


@pytest.mark.asyncio
async def test_collect_urls_deduplicates():
    p = _pipeline()
    scanner = MagicMock()
    urls = await p._collect_urls(scanner, TARGET)
    assert len(urls) == len(set(urls))


@pytest.mark.asyncio
async def test_collect_urls_wordlist_expansion():
    p = _pipeline()
    scanner = MagicMock()
    urls = await p._collect_urls(scanner, TARGET)
    # At minimum base URL + wordlist paths
    assert len(urls) > 1


@pytest.mark.asyncio
async def test_collect_urls_crawl_adds_discovered(tmp_path):
    """Crawler-discovered URLs are appended after wordlist URLs."""
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    p = Pipeline(cfg, crawl=True)

    crawled_url = f"{TARGET}/discovered-page"
    mock_pages  = [MagicMock(url=crawled_url)]

    with patch("core.pipeline.Crawler") as MockCrawler:
        MockCrawler.return_value.run = AsyncMock(return_value=mock_pages)
        MockCrawler.discovered_urls  = MagicMock(return_value=[crawled_url])
        scanner = MagicMock()
        urls = await p._collect_urls(scanner, TARGET)

    assert crawled_url in urls


# ─── Pipeline.run — end-to-end ────────────────────────────────────────────────

def _patch_scanner_responses(url_body_map: dict[str, str]):
    """
    Return a Scanner *class* mock whose instances respond per url_body_map.
    Usage: patch("core.pipeline.Scanner", new_callable=lambda: lambda: MockClass)
    Actually returns a MagicMock that, when called (Scanner(config)), returns
    an async-context-manager mock instance.
    """
    async def _get(url: str) -> ScanResult:
        body = url_body_map.get(url, CLEAN_HTML)
        return _sr(url, body=body)

    instance = MagicMock()
    instance.get = _get
    async def _scan_urls(urls):
        return [await _get(u) for u in urls]
    instance.scan_urls = _scan_urls
    instance.__aenter__ = AsyncMock(return_value=instance)
    instance.__aexit__  = AsyncMock(return_value=False)

    # Scanner class mock: Scanner(config) → instance
    cls_mock = MagicMock(return_value=instance)
    return cls_mock


@pytest.mark.asyncio
async def test_run_returns_pipeline_result(tmp_path):
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    p = _pipeline(cfg)
    with patch("core.pipeline.Scanner", new=_patch_scanner_responses({})):
        result = await p.run(TARGET)
    assert isinstance(result, PipelineResult)


@pytest.mark.asyncio
async def test_run_no_error_on_clean_target(tmp_path):
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    p = _pipeline(cfg)
    with patch("core.pipeline.Scanner", new=_patch_scanner_responses({})):
        result = await p.run(TARGET)
    assert result.error is None


@pytest.mark.asyncio
async def test_run_produces_report_file(tmp_path):
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    p = _pipeline(cfg)
    with patch("core.pipeline.Scanner", new=_patch_scanner_responses({})):
        result = await p.run(TARGET)
    assert result.report_path is not None
    assert result.report_path.exists()


@pytest.mark.asyncio
async def test_run_report_is_valid_json(tmp_path):
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    p = _pipeline(cfg)
    with patch("core.pipeline.Scanner", new=_patch_scanner_responses({})):
        result = await p.run(TARGET)
    with open(result.report_path) as f:
        data = json.load(f)
    assert "meta" in data
    assert "summary" in data
    assert "endpoints" in data


@pytest.mark.asyncio
async def test_run_urls_scanned_nonzero(tmp_path):
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    p = _pipeline(cfg)
    with patch("core.pipeline.Scanner", new=_patch_scanner_responses({})):
        result = await p.run(TARGET)
    assert result.urls_scanned > 0


@pytest.mark.asyncio
async def test_run_scoring_results_match_urls_scanned(tmp_path):
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    p = _pipeline(cfg)
    with patch("core.pipeline.Scanner", new=_patch_scanner_responses({})):
        result = await p.run(TARGET)
    assert len(result.scoring_results) == result.urls_scanned


@pytest.mark.asyncio
async def test_run_timestamps_set(tmp_path):
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    p = _pipeline(cfg)
    with patch("core.pipeline.Scanner", new=_patch_scanner_responses({})):
        result = await p.run(TARGET)
    assert result.started_at != ""
    assert result.finished_at != ""


@pytest.mark.asyncio
async def test_run_detects_admin_panel(tmp_path):
    """Admin panel body should produce at least one non-zero admin score."""
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    p = _pipeline(cfg)
    admin_url = f"{TARGET}/wp-admin"
    body_map  = {admin_url: ADMIN_HTML}

    with patch("core.pipeline.Scanner", new=_patch_scanner_responses(body_map)):
        result = await p.run(TARGET)

    admin_scores = [
        r.category_scores.get("admin", 0.0)
        for r in result.scoring_results
        if r.url == admin_url
    ]
    assert any(s > 0.0 for s in admin_scores)


@pytest.mark.asyncio
async def test_run_detects_directory_listing(tmp_path):
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    p = _pipeline(cfg)
    # Use base URL (always scanned) with dir-listing body
    body_map = {TARGET: DIR_HTML}

    with patch("core.pipeline.Scanner", new=_patch_scanner_responses(body_map)):
        result = await p.run(TARGET)

    dir_scores = [
        r.category_scores.get("dir_listing", 0.0)
        for r in result.scoring_results
        if r.url == TARGET
    ]
    assert any(s > 0.0 for s in dir_scores)


@pytest.mark.asyncio
async def test_run_report_meta_target_url(tmp_path):
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    p = _pipeline(cfg)
    with patch("core.pipeline.Scanner", new=_patch_scanner_responses({})):
        result = await p.run(TARGET)
    assert TARGET in result.report["meta"]["target_url"]


@pytest.mark.asyncio
async def test_run_no_duplicate_urls(tmp_path):
    """Each URL must appear exactly once in scoring_results."""
    cfg = {**BASE_CONFIG, "reporting": {**BASE_CONFIG["reporting"],
                                         "output_dir": str(tmp_path)}}
    p = _pipeline(cfg)
    with patch("core.pipeline.Scanner", new=_patch_scanner_responses({})):
        result = await p.run(TARGET)
    scored_urls = [r.url for r in result.scoring_results]
    assert len(scored_urls) == len(set(scored_urls))


# ─── print_summary ────────────────────────────────────────────────────────────

def _make_result(tmp_path: Path) -> PipelineResult:
    from core.scorer import ScoringResult, Severity, Label
    from core.detector import DetectionResult, Category
    from core.analyzer import AnalysisResult, TitleInfo, HeaderAudit, ScriptInfo, KeywordInfo

    def _sr2(url):
        return ScanResult(url=url, status_code=200, headers={}, body="",
                          elapsed_ms=5.0, redirected_url=None, error=None)

    def _det(url):
        cats = {c.value: 0.0 for c in Category}
        return DetectionResult(url=url, category_scores=cats, composite_score=0.0,
                               dominant_category=None, matched_patterns=[],
                               scan_result=_sr2(url))

    def _ana(url):
        return AnalysisResult(url=url, status_code=200,
                              title=TitleInfo(raw="", lower=""),
                              headers=HeaderAudit())

    sr = ScoringResult(
        url="http://t.local/admin", category_scores={c.value: 0.0 for c in Category},
        composite_score=0.85, severity=Severity.CRITICAL, label=Label.VULNERABLE,
        confidence=0.92, dominant_category="admin",
        analyser_bonuses={c.value: 0.0 for c in Category},
        threshold_used=0.70,
        detection_result=_det("http://t.local/admin"),
        analysis_result=_ana("http://t.local/admin"),
    )
    from core.reporter import Reporter
    reporter = Reporter(BASE_CONFIG | {"reporting": {
        **BASE_CONFIG["reporting"], "output_dir": str(tmp_path)}})
    report = reporter.build([sr], TARGET)
    return PipelineResult(
        target_url=TARGET, scoring_results=[sr], report=report,
        report_path=tmp_path / "test.json",
        started_at="2024-01-01T10:00:00Z",
        finished_at="2024-01-01T10:05:00Z",
        urls_scanned=1,
    )


def test_print_summary_runs_without_error(tmp_path, capsys):
    result = _make_result(tmp_path)
    print_summary(result)
    out = capsys.readouterr().out
    assert "HybriScan" in out
    assert TARGET in out


def test_print_summary_shows_vulnerable_count(tmp_path, capsys):
    result = _make_result(tmp_path)
    print_summary(result)
    out = capsys.readouterr().out
    assert "1" in out   # 1 vulnerable endpoint


def test_print_summary_shows_report_path(tmp_path, capsys):
    result = _make_result(tmp_path)
    print_summary(result)
    out = capsys.readouterr().out
    assert "test.json" in out


def test_print_summary_error_branch(capsys):
    result = PipelineResult(
        target_url=TARGET, started_at="s", finished_at="f",
        error="Connection refused",
    )
    print_summary(result)
    out = capsys.readouterr().out
    assert "ERROR" in out


def test_print_summary_verbose_shows_scores(tmp_path, capsys):
    result = _make_result(tmp_path)
    print_summary(result, verbose=True)
    out = capsys.readouterr().out
    assert "admin" in out


# ─── apply_cli_overrides (main.py) ────────────────────────────────────────────

def test_apply_cli_overrides_threshold():
    import types
    from main import apply_cli_overrides
    args = types.SimpleNamespace(
        threshold=0.75, concurrency=None, depth=None,
        output=None, payloads=False, verbose=False,
    )
    cfg = apply_cli_overrides({"scoring": {}}, args)
    assert cfg["scoring"]["initial_threshold"] == 0.75


def test_apply_cli_overrides_concurrency():
    import types
    from main import apply_cli_overrides
    args = types.SimpleNamespace(
        threshold=None, concurrency=20, depth=None,
        output=None, payloads=False, verbose=False,
    )
    cfg = apply_cli_overrides({}, args)
    assert cfg["scanner"]["concurrency"] == 20


def test_apply_cli_overrides_payloads_flag():
    import types
    from main import apply_cli_overrides
    args = types.SimpleNamespace(
        threshold=None, concurrency=None, depth=None,
        output=None, payloads=True, verbose=False,
    )
    cfg = apply_cli_overrides({}, args)
    assert cfg["payloads"]["enabled"] is True


def test_apply_cli_overrides_depth():
    import types
    from main import apply_cli_overrides
    args = types.SimpleNamespace(
        threshold=None, concurrency=None, depth=3,
        output=None, payloads=False, verbose=False,
    )
    cfg = apply_cli_overrides({}, args)
    assert cfg["crawler"]["max_depth"] == 3


def test_apply_cli_overrides_no_change_when_none():
    import types
    from main import apply_cli_overrides
    args = types.SimpleNamespace(
        threshold=None, concurrency=None, depth=None,
        output=None, payloads=False, verbose=False,
    )
    cfg = apply_cli_overrides({"scoring": {"initial_threshold": 0.70}}, args)
    assert cfg["scoring"]["initial_threshold"] == 0.70
