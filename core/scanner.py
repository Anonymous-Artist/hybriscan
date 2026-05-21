"""
core/scanner.py
───────────────
Async HTTP engine for HybriScan.

Responsibilities
----------------
- Manage a single aiohttp.ClientSession per scan run (open/close lifecycle).
- Enforce concurrency via asyncio.Semaphore (limit from settings.yaml).
- Execute HTTP GET requests with timeout, retry, and exponential back-off.
- Return structured ScanResult dataclasses consumed by detector / analyzer.
- Emit structured log events at DEBUG / INFO / WARNING level.

This module performs NO vulnerability detection — it is pure transport.
Detection logic lives in core/detector.py (Phase 4).
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector

from core.utils import get_logger, normalise_url

# Module-level logger — configured properly once main.py calls get_logger
# with the full config dict.  Falls back to INFO/stdout until then.
_log = get_logger(__name__)


# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """
    Structured result for a single HTTP request.

    Consumed downstream by analyzer.py and detector.py.
    All fields are populated regardless of success/failure so that
    the reporting layer always receives a complete record.
    """
    url: str
    status_code: int | None          # None on network error
    headers: dict[str, str]          # response headers (lower-cased keys)
    body: str                        # decoded response body (empty on error)
    elapsed_ms: float                # total request time in milliseconds
    redirected_url: str | None       # final URL after redirects, if any
    error: str | None                # error description, None on success
    retries_used: int = 0            # number of retry attempts consumed

    @property
    def success(self) -> bool:
        """True if the request completed with an HTTP status code."""
        return self.status_code is not None and self.error is None


@dataclass
class ScannerConfig:
    """
    Typed view of the scanner section of settings.yaml.
    Constructed by Scanner.__init__ from the raw config dict.
    """
    user_agent: str   = "HybriScan/1.0"
    timeout: int      = 10
    max_retries: int  = 2
    retry_backoff: float = 1.5
    concurrency: int  = 10
    follow_redirects: bool = True
    max_redirects: int = 5
    verify_ssl: bool  = False


# ─── Scanner ──────────────────────────────────────────────────────────────────

class Scanner:
    """
    Async HTTP engine.  Manages one aiohttp session for the lifetime of a scan.

    Usage (async context manager)::

        async with Scanner(config) as scanner:
            result = await scanner.get("http://target.local/admin")

    Or batch::

        async with Scanner(config) as scanner:
            results = await scanner.scan_urls(url_list)
    """

    def __init__(self, config: dict[str, Any]) -> None:
        """
        Args:
            config: Full settings dict (from utils.load_config).
        """
        raw = config.get("scanner", {})
        self._cfg = ScannerConfig(
            user_agent      = raw.get("user_agent", ScannerConfig.user_agent),
            timeout         = int(raw.get("timeout", ScannerConfig.timeout)),
            max_retries     = int(raw.get("max_retries", ScannerConfig.max_retries)),
            retry_backoff   = float(raw.get("retry_backoff", ScannerConfig.retry_backoff)),
            concurrency     = int(raw.get("concurrency", ScannerConfig.concurrency)),
            follow_redirects= bool(raw.get("follow_redirects", ScannerConfig.follow_redirects)),
            max_redirects   = int(raw.get("max_redirects", ScannerConfig.max_redirects)),
            verify_ssl      = bool(raw.get("verify_ssl", ScannerConfig.verify_ssl)),
        )
        self._session: ClientSession | None = None
        self._semaphore: asyncio.Semaphore | None = None

        # Re-attach logger with full config so file handler is active if set
        global _log
        _log = get_logger(__name__, config)
        _log.debug("ScannerConfig loaded: %s", self._cfg)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def __aenter__(self) -> "Scanner":
        await self._open()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self._close()

    async def _open(self) -> None:
        """Create the aiohttp session and concurrency semaphore."""
        self._semaphore = asyncio.Semaphore(self._cfg.concurrency)
        connector = TCPConnector(ssl=self._cfg.verify_ssl, limit=self._cfg.concurrency)
        timeout = ClientTimeout(total=self._cfg.timeout)
        headers = {"User-Agent": self._cfg.user_agent}
        self._session = ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            trust_env=True,            # respect HTTP_PROXY env var in lab setups
        )
        _log.info("HTTP session opened (concurrency=%d, timeout=%ds)",
                  self._cfg.concurrency, self._cfg.timeout)

    async def _close(self) -> None:
        """Cleanly close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
            _log.info("HTTP session closed.")

    # ── Core Request ──────────────────────────────────────────────────────────

    async def get(self, url: str) -> ScanResult:
        """
        Issue an HTTP GET with retry and exponential back-off.

        Concurrency is bounded by the semaphore set at session open.
        Each attempt captures status, headers, body, and elapsed time.
        On exhausting retries, returns a ScanResult with error populated.

        Args:
            url: Fully-qualified target URL.

        Returns:
            ScanResult dataclass.
        """
        if self._session is None or self._semaphore is None:
            raise RuntimeError("Scanner not opened — use 'async with Scanner(config)'.")

        url = normalise_url(url)
        attempt = 0
        last_error: str = "Unknown error"

        async with self._semaphore:
            while attempt <= self._cfg.max_retries:
                t_start = time.perf_counter()
                try:
                    result = await self._attempt_get(url, t_start, attempt)
                    if result.success:
                        return result
                    # Non-success but got HTTP response (e.g. 5xx) — log and retry
                    last_error = result.error or f"HTTP {result.status_code}"
                    _log.warning("Attempt %d/%d — %s — %s",
                                 attempt + 1, self._cfg.max_retries + 1, url, last_error)

                except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                    _log.warning("Attempt %d/%d — %s — %s",
                                 attempt + 1, self._cfg.max_retries + 1, url, last_error)

                attempt += 1
                if attempt <= self._cfg.max_retries:
                    backoff = self._cfg.retry_backoff ** attempt
                    _log.debug("Backing off %.2fs before retry %d", backoff, attempt)
                    await asyncio.sleep(backoff)

        # All attempts exhausted
        _log.error("All %d attempts failed for %s — %s",
                   self._cfg.max_retries + 1, url, last_error)
        return ScanResult(
            url=url,
            status_code=None,
            headers={},
            body="",
            elapsed_ms=0.0,
            redirected_url=None,
            error=last_error,
            retries_used=attempt - 1,
        )

    async def _attempt_get(
        self, url: str, t_start: float, attempt: int
    ) -> ScanResult:
        """
        Execute a single HTTP GET attempt.

        Args:
            url:     Target URL (already normalised).
            t_start: perf_counter timestamp at attempt start.
            attempt: Zero-based attempt index (for logging).

        Returns:
            ScanResult populated from the HTTP response.
        """
        allow_redirects = self._cfg.follow_redirects
        max_redirects   = self._cfg.max_redirects

        async with self._session.get(  # type: ignore[union-attr]
            url,
            allow_redirects=allow_redirects,
            max_redirects=max_redirects,
        ) as resp:
            body = await resp.text(errors="replace")
            elapsed_ms = (time.perf_counter() - t_start) * 1000
            headers = {k.lower(): v for k, v in resp.headers.items()}
            redirected = str(resp.url) if str(resp.url) != url else None

            _log.debug(
                "[%d] GET %s → %s (%.1fms)",
                resp.status, url, redirected or "no redirect", elapsed_ms,
            )

            # Treat 5xx as soft errors (retryable); 4xx as definitive
            error: str | None = None
            if resp.status >= 500:
                error = f"Server error HTTP {resp.status}"

            return ScanResult(
                url=url,
                status_code=resp.status,
                headers=headers,
                body=body,
                elapsed_ms=round(elapsed_ms, 2),
                redirected_url=redirected,
                error=error,
                retries_used=attempt,
            )

    # ── Batch Scan ────────────────────────────────────────────────────────────

    async def scan_urls(self, urls: list[str]) -> list[ScanResult]:
        """
        Scan a list of URLs concurrently, respecting the semaphore limit.

        Args:
            urls: List of target URLs (wordlist-expanded or crawler-produced).

        Returns:
            List of ScanResult in the same order as input.
        """
        _log.info("Starting batch scan: %d URLs", len(urls))
        tasks = [self.get(url) for url in urls]
        results: list[ScanResult] = await asyncio.gather(*tasks)
        success  = sum(1 for r in results if r.success)
        failed   = len(results) - success
        _log.info("Batch complete: %d succeeded, %d failed", success, failed)
        return results
