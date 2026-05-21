"""
tests/test_scanner.py
─────────────────────
Unit tests for core/scanner.py.

Uses aiohttp's built-in test utilities (no real HTTP traffic).
Run with:  pytest tests/test_scanner.py -v
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.scanner import Scanner, ScanResult, ScannerConfig
from core.utils import normalise_url


# ─── Fixtures ─────────────────────────────────────────────────────────────────

BASE_CONFIG = {
    "scanner": {
        "user_agent": "HybriScan-Test/1.0",
        "timeout": 5,
        "max_retries": 1,
        "retry_backoff": 1.0,
        "concurrency": 2,
        "follow_redirects": True,
        "max_redirects": 3,
        "verify_ssl": False,
    },
    "logging": {"level": "WARNING", "log_to_file": False},
}


def _mock_response(status: int = 200, body: str = "<html>ok</html>",
                   headers: dict | None = None) -> MagicMock:
    """Build a mock aiohttp response object."""
    resp = MagicMock()
    resp.status = status
    resp.url = MagicMock()
    resp.url.__str__ = MagicMock(return_value="http://target.local/page")
    resp.headers = headers or {"Content-Type": "text/html"}
    resp.text = AsyncMock(return_value=body)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


# ─── ScannerConfig ────────────────────────────────────────────────────────────

def test_scanner_config_defaults():
    scanner = Scanner({"scanner": {}})
    cfg = scanner._cfg
    assert cfg.timeout == 10
    assert cfg.max_retries == 2
    assert cfg.concurrency == 10


def test_scanner_config_from_dict():
    scanner = Scanner(BASE_CONFIG)
    assert scanner._cfg.timeout == 5
    assert scanner._cfg.max_retries == 1
    assert scanner._cfg.concurrency == 2


# ─── normalise_url ────────────────────────────────────────────────────────────

def test_normalise_url_adds_scheme():
    assert normalise_url("example.com").startswith("http://")


def test_normalise_url_strips_trailing_slash():
    assert not normalise_url("http://example.com/").endswith("/")


def test_normalise_url_lowercases_host():
    assert "EXAMPLE" not in normalise_url("http://EXAMPLE.COM/Path")


# ─── ScanResult ───────────────────────────────────────────────────────────────

def test_scan_result_success_property():
    r = ScanResult(url="http://x.com", status_code=200, headers={},
                   body="ok", elapsed_ms=10.0, redirected_url=None, error=None)
    assert r.success is True


def test_scan_result_failure_on_error():
    r = ScanResult(url="http://x.com", status_code=None, headers={},
                   body="", elapsed_ms=0.0, redirected_url=None,
                   error="ConnectionError")
    assert r.success is False


def test_scan_result_failure_on_5xx():
    r = ScanResult(url="http://x.com", status_code=503, headers={},
                   body="", elapsed_ms=5.0, redirected_url=None,
                   error="Server error HTTP 503")
    assert r.success is False


# ─── Scanner.get ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_success():
    scanner = Scanner(BASE_CONFIG)
    mock_resp = _mock_response(200, "<html>admin</html>")

    with patch("aiohttp.ClientSession.get", return_value=mock_resp):
        async with scanner:
            result = await scanner.get("http://target.local/admin")

    assert result.success
    assert result.status_code == 200
    assert "admin" in result.body


@pytest.mark.asyncio
async def test_get_returns_result_on_404():
    scanner = Scanner(BASE_CONFIG)
    mock_resp = _mock_response(404, "Not Found")

    with patch("aiohttp.ClientSession.get", return_value=mock_resp):
        async with scanner:
            result = await scanner.get("http://target.local/missing")

    # 404 is a definitive client error — not retried, success=True (got HTTP response)
    assert result.status_code == 404
    assert result.error is None   # only 5xx populates error


@pytest.mark.asyncio
async def test_get_retries_on_5xx():
    scanner = Scanner(BASE_CONFIG)
    call_count = 0

    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return _mock_response(503, "Server Error")

    with patch("aiohttp.ClientSession.get", side_effect=side_effect):
        async with scanner:
            result = await scanner.get("http://target.local/flaky")

    # max_retries=1 → 2 total attempts
    assert call_count == 2
    # After all retries exhausted, scanner returns error result
    assert result.success is False
    assert "503" in (result.error or "")


@pytest.mark.asyncio
async def test_get_returns_error_on_network_failure():
    import aiohttp as _aiohttp
    scanner = Scanner(BASE_CONFIG)

    with patch("aiohttp.ClientSession.get",
               side_effect=_aiohttp.ClientConnectionError("refused")):
        async with scanner:
            result = await scanner.get("http://unreachable.local/")

    assert result.success is False
    assert result.status_code is None
    assert "ClientConnectionError" in (result.error or "")


# ─── Scanner.scan_urls ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_urls_batch():
    scanner = Scanner(BASE_CONFIG)
    urls = [
        "http://target.local/admin",
        "http://target.local/login",
        "http://target.local/",
    ]
    mock_resp = _mock_response(200, "<html>page</html>")

    with patch("aiohttp.ClientSession.get", return_value=mock_resp):
        async with scanner:
            results = await scanner.scan_urls(urls)

    assert len(results) == 3
    assert all(r.status_code == 200 for r in results)


@pytest.mark.asyncio
async def test_scanner_requires_context_manager():
    scanner = Scanner(BASE_CONFIG)
    with pytest.raises(RuntimeError, match="not opened"):
        await scanner.get("http://target.local/")
