"""
tests/test_crawler.py
─────────────────────
Unit tests for core/crawler.py.

All tests use mock Scanner responses — no real HTTP traffic.
Run with:  pytest tests/test_crawler.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from core.crawler import (
    Crawler,
    CrawlerConfig,
    CrawlPage,
    _normalise_internal,
    _has_filtered_extension,
    _origin,
    _RobotsGuard,
)
from core.scanner import ScanResult


# ─── Fixtures ─────────────────────────────────────────────────────────────────

BASE_CONFIG = {
    "scanner": {
        "user_agent": "HybriScan-Test/1.0",
        "timeout": 5,
        "max_retries": 0,
        "retry_backoff": 1.0,
        "concurrency": 2,
        "follow_redirects": True,
        "max_redirects": 3,
        "verify_ssl": False,
    },
    "crawler": {
        "max_depth": 2,
        "max_pages": 50,
        "respect_robots_txt": False,   # off by default in tests
        "url_filter_extensions": [".png", ".css", ".js"],
    },
    "logging": {"level": "WARNING", "log_to_file": False},
}

BASE_URL = "http://target.local"


def _make_result(url: str, body: str = "<html></html>",
                 status: int = 200, error: str | None = None) -> ScanResult:
    return ScanResult(
        url=url, status_code=status if not error else None,
        headers={}, body=body, elapsed_ms=10.0,
        redirected_url=None, error=error,
    )


def _mock_scanner(results: list[ScanResult]) -> MagicMock:
    """Return a mock Scanner whose get() returns results in sequence."""
    scanner = MagicMock()
    scanner.get = AsyncMock(side_effect=results)
    return scanner


# ─── _origin ──────────────────────────────────────────────────────────────────

def test_origin_extracts_scheme_and_host():
    assert _origin("http://target.local/admin/panel") == "http://target.local"


def test_origin_includes_port():
    assert _origin("http://target.local:8080/path") == "http://target.local:8080"


# ─── _normalise_internal ──────────────────────────────────────────────────────

def test_normalise_relative_href():
    result = _normalise_internal("/login", "http://target.local/home")
    assert result == "http://target.local/login"


def test_normalise_absolute_same_origin():
    result = _normalise_internal("http://target.local/admin", "http://target.local/")
    assert result == "http://target.local/admin"


def test_normalise_rejects_external():
    result = _normalise_internal("http://evil.com/steal", "http://target.local/")
    assert result is None


def test_normalise_rejects_javascript():
    assert _normalise_internal("javascript:void(0)", "http://target.local/") is None


def test_normalise_rejects_mailto():
    assert _normalise_internal("mailto:admin@x.com", "http://target.local/") is None


def test_normalise_strips_fragment():
    result = _normalise_internal("/page#section", "http://target.local/")
    assert result is not None
    assert "#" not in result


def test_normalise_empty_href():
    assert _normalise_internal("", "http://target.local/") is None


def test_normalise_fragment_only():
    assert _normalise_internal("#top", "http://target.local/") is None


# ─── _has_filtered_extension ──────────────────────────────────────────────────

def test_filters_png():
    assert _has_filtered_extension("http://t.local/img/logo.png", [".png"])


def test_filters_css():
    assert _has_filtered_extension("http://t.local/style.CSS", [".css"])


def test_allows_html_path():
    assert not _has_filtered_extension("http://t.local/admin", [".png", ".css"])


def test_ignores_query_string_in_extension_check():
    # /file.png?v=2 should still be filtered
    assert _has_filtered_extension("http://t.local/img/bg.png?v=2", [".png"])


# ─── CrawlerConfig ────────────────────────────────────────────────────────────

def test_crawler_config_from_dict():
    c = Crawler(BASE_CONFIG, BASE_URL)
    assert c._cfg.max_depth == 2
    assert c._cfg.max_pages == 50
    assert c._cfg.respect_robots_txt is False


def test_crawler_config_defaults():
    c = Crawler({"scanner": {}, "logging": {"level": "WARNING", "log_to_file": False}},
                BASE_URL)
    assert c._cfg.max_depth == 2
    assert c._cfg.max_pages == 100


# ─── _extract_links ───────────────────────────────────────────────────────────

def test_extract_links_returns_internal_only():
    html = """
    <html><body>
      <a href="/admin">Admin</a>
      <a href="http://target.local/login">Login</a>
      <a href="http://external.com/steal">External</a>
      <a href="javascript:void(0)">JS</a>
    </body></html>
    """
    crawler = Crawler(BASE_CONFIG, BASE_URL)
    links = crawler._extract_links(html, BASE_URL)
    assert "http://target.local/admin" in links
    assert "http://target.local/login" in links
    assert all("external.com" not in l for l in links)


def test_extract_links_deduplicates():
    html = """
    <html><body>
      <a href="/page">A</a>
      <a href="/page">B</a>
      <a href="/page/">C</a>
    </body></html>
    """
    crawler = Crawler(BASE_CONFIG, BASE_URL)
    links = crawler._extract_links(html, BASE_URL)
    assert links.count("http://target.local/page") == 1


def test_extract_links_filters_extensions():
    html = """
    <html><body>
      <a href="/style.css">CSS</a>
      <a href="/script.js">JS</a>
      <a href="/admin">Admin</a>
    </body></html>
    """
    crawler = Crawler(BASE_CONFIG, BASE_URL)
    links = crawler._extract_links(html, BASE_URL)
    assert not any(l.endswith(".css") or l.endswith(".js") for l in links)
    assert "http://target.local/admin" in links


def test_extract_links_empty_html():
    crawler = Crawler(BASE_CONFIG, BASE_URL)
    links = crawler._extract_links("", BASE_URL)
    assert links == []


# ─── Crawler.run ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_single_page_no_links():
    """Base URL returns a page with no internal links — only 1 page crawled."""
    crawler = Crawler(BASE_CONFIG, BASE_URL)
    scanner = _mock_scanner([
        _make_result(BASE_URL, body="<html><body>No links here.</body></html>"),
    ])
    pages = await crawler.run(scanner)
    assert len(pages) == 1
    assert pages[0].url == BASE_URL
    assert pages[0].depth == 0


@pytest.mark.asyncio
async def test_run_follows_internal_links():
    """Base page links to /admin — crawler should fetch both."""
    html_base = '<html><body><a href="/admin">Admin</a></body></html>'
    html_admin = "<html><body>Admin Panel</body></html>"

    crawler = Crawler(BASE_CONFIG, BASE_URL)
    scanner = _mock_scanner([
        _make_result(BASE_URL, body=html_base),
        _make_result(f"{BASE_URL}/admin", body=html_admin),
    ])
    pages = await crawler.run(scanner)
    urls = [p.url for p in pages]
    assert BASE_URL in urls
    assert f"{BASE_URL}/admin" in urls


@pytest.mark.asyncio
async def test_run_respects_max_depth():
    """Links beyond max_depth must not be enqueued."""
    # depth 0 → depth 1 → depth 2 (max) → depth 3 must be ignored
    cfg = {**BASE_CONFIG, "crawler": {**BASE_CONFIG["crawler"], "max_depth": 1}}

    html_d0 = '<html><body><a href="/d1">D1</a></body></html>'
    html_d1 = '<html><body><a href="/d2">D2</a></body></html>'

    crawler = Crawler(cfg, BASE_URL)
    scanner = _mock_scanner([
        _make_result(BASE_URL, body=html_d0),
        _make_result(f"{BASE_URL}/d1", body=html_d1),
        # /d2 should never be fetched
    ])
    pages = await crawler.run(scanner)
    urls = [p.url for p in pages]
    assert f"{BASE_URL}/d2" not in urls


@pytest.mark.asyncio
async def test_run_respects_max_pages():
    """Crawler must stop at max_pages cap."""
    cfg = {**BASE_CONFIG, "crawler": {**BASE_CONFIG["crawler"], "max_pages": 1}}

    html_base = '<html><body><a href="/admin">Admin</a></body></html>'
    crawler = Crawler(cfg, BASE_URL)
    scanner = _mock_scanner([
        _make_result(BASE_URL, body=html_base),
    ])
    pages = await crawler.run(scanner)
    assert len(pages) == 1


@pytest.mark.asyncio
async def test_run_no_duplicate_fetches():
    """A URL appearing in multiple pages must only be fetched once."""
    # Both /a and /b link to /shared — /shared should be fetched once
    html_base = (
        '<html><body>'
        '<a href="/a">A</a><a href="/b">B</a>'
        '</body></html>'
    )
    html_a = '<html><body><a href="/shared">Shared</a></body></html>'
    html_b = '<html><body><a href="/shared">Shared</a></body></html>'
    html_shared = "<html><body>Shared page</body></html>"

    cfg = {**BASE_CONFIG, "crawler": {**BASE_CONFIG["crawler"], "max_depth": 2}}
    crawler = Crawler(cfg, BASE_URL)
    scanner = _mock_scanner([
        _make_result(BASE_URL, body=html_base),
        _make_result(f"{BASE_URL}/a", body=html_a),
        _make_result(f"{BASE_URL}/b", body=html_b),
        _make_result(f"{BASE_URL}/shared", body=html_shared),
    ])
    pages = await crawler.run(scanner)
    fetched_urls = [p.url for p in pages]
    assert fetched_urls.count(f"{BASE_URL}/shared") == 1


@pytest.mark.asyncio
async def test_run_skips_failed_pages_gracefully():
    """A network failure on a page should not abort the crawl."""
    html_base = '<html><body><a href="/admin">Admin</a></body></html>'
    crawler = Crawler(BASE_CONFIG, BASE_URL)
    scanner = _mock_scanner([
        _make_result(BASE_URL, body=html_base),
        _make_result(f"{BASE_URL}/admin", error="ConnectionRefused"),
    ])
    pages = await crawler.run(scanner)
    assert len(pages) == 2
    assert pages[1].result.success is False


# ─── discovered_urls ──────────────────────────────────────────────────────────

def test_discovered_urls_returns_flat_list():
    pages = [
        CrawlPage(url="http://t.local/", depth=0, result=_make_result("http://t.local/")),
        CrawlPage(url="http://t.local/admin", depth=1, result=_make_result("http://t.local/admin")),
    ]
    assert Crawler.discovered_urls(pages) == ["http://t.local/", "http://t.local/admin"]
