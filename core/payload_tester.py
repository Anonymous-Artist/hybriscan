"""
core/payload_tester.py
──────────────────────
Lightweight payload testing engine for HybriScan.

Design philosophy
-----------------
This module implements *indicator-based* payload testing — a research-safe
approach that:

  1. Fetches a clean baseline response for a URL.
  2. Re-fetches the URL with a small, controlled payload appended to each
     discovered query parameter.
  3. Compares the payload response against the baseline on four dimensions:
       - status code change
       - content-length change (> 5% delta)
       - SQL error signatures in the response body
       - reflection of the injected payload string in the response body
  4. Returns structured PayloadResult records consumed by the scorer /
     reporter without making any automated exploitation attempt.

What this module does NOT do
-----------------------------
- No UNION-based data extraction.
- No stacked queries or multi-statement execution.
- No session hijacking or cookie theft.
- No automated exploitation of detected anomalies.
- No destructive (DELETE / DROP) payloads.

Integration
-----------
  async with Scanner(config) as scanner:
      tester  = PayloadTester(config)
      results = await tester.test_url(scanner, url, baseline_result)

All results are passed to the reporter as supplementary evidence fields.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.scanner import ScanResult, Scanner
from core.utils import get_logger

_log = get_logger(__name__)


# ─── Compiled SQL error signatures ────────────────────────────────────────────
# Subset of detector.py SQLI_PATTERNS — reproduced here for standalone use
# without importing the full detection engine into the test loop.

_SQL_ERROR_PATTERNS: tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE) for p in (
        r"you have an error in your sql syntax",
        r"warning:\s*mysql_",
        r"ORA-\d{5}:",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"pg_query\(\).*error",
        r"sqlite_(?:exception|error)",
        r"microsoft sql server.*error",
        r"supplied argument is not a valid mysql result resource",
    )
)


# ─── Data structures ──────────────────────────────────────────────────────────

@dataclass
class Payload:
    """A single test payload with its category and string value."""
    category: str    # "sqli" | "xss"
    value:    str    # raw payload string to inject


@dataclass
class PayloadResult:
    """
    Comparison result for one (URL, parameter, payload) triple.

    All fields describe *observed differences* between the baseline and
    payload response — no classification decisions are made here.
    """
    url:              str
    parameter:        str        # query parameter that received the payload
    payload:          Payload
    baseline_status:  int | None
    payload_status:   int | None
    status_changed:   bool
    baseline_length:  int        # len(baseline body)
    payload_length:   int        # len(payload body)
    length_delta_pct: float      # abs % change in content length
    length_changed:   bool       # True if delta > LENGTH_CHANGE_THRESHOLD
    sql_error_found:  bool       # SQL error signature in payload response
    reflection_found: bool       # payload string reflected verbatim in body
    error:            str | None # network/request error if fetch failed


@dataclass
class UrlTestSummary:
    """
    Aggregated payload test results for a single URL.

    Consumed by the reporter as supplementary evidence.
    """
    url:               str
    parameters_tested: list[str]
    total_probes:      int
    anomalies:         list[PayloadResult]    = field(default_factory=list)
    sql_error_count:   int                    = 0
    reflection_count:  int                    = 0
    status_change_count: int                  = 0


# ─── Config ───────────────────────────────────────────────────────────────────

_LENGTH_CHANGE_THRESHOLD: float = 0.05   # 5% content-length delta flags an anomaly

@dataclass
class PayloadConfig:
    """Typed view of settings.yaml[payloads]."""
    enabled:           bool  = False
    sqli_payload_file: str   = "payloads/sqli.txt"
    xss_payload_file:  str   = "payloads/xss.txt"
    compare_baseline:  bool  = True


def _parse_config(config: dict) -> PayloadConfig:
    pc = config.get("payloads", {})
    return PayloadConfig(
        enabled           = bool(pc.get("enabled", False)),
        sqli_payload_file = str(pc.get("sqli_payload_file", "payloads/sqli.txt")),
        xss_payload_file  = str(pc.get("xss_payload_file",  "payloads/xss.txt")),
        compare_baseline  = bool(pc.get("compare_baseline", True)),
    )


# ─── Payload loading ──────────────────────────────────────────────────────────

def load_payloads(filepath: str, category: str) -> list[Payload]:
    """
    Load payloads from a plain-text file (one per line).

    Lines beginning with '#' and blank lines are skipped.

    Args:
        filepath: Path to the payload file.
        category: Category label ("sqli" or "xss") for all loaded payloads.

    Returns:
        List of Payload objects; empty list if the file does not exist.
    """
    path = Path(filepath)
    if not path.exists():
        _log.warning("Payload file not found: %s", filepath)
        return []
    payloads: list[Payload] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                payloads.append(Payload(category=category, value=line))
    _log.debug("Loaded %d %s payloads from %s", len(payloads), category, filepath)
    return payloads


# ─── URL manipulation ─────────────────────────────────────────────────────────

def extract_query_params(url: str) -> list[str]:
    """
    Return the list of query parameter names present in a URL.

    Args:
        url: Absolute URL string.

    Returns:
        List of unique parameter names (order: first occurrence).
    """
    qs = urlparse(url).query
    return list(parse_qs(qs, keep_blank_values=True).keys())


def inject_payload(url: str, param: str, payload_value: str) -> str:
    """
    Return a new URL with *param* replaced by the given payload value.

    All other parameters are preserved unchanged.

    Args:
        url:           Original URL.
        param:         Query parameter name to replace.
        payload_value: Payload string to set as the parameter value.

    Returns:
        Modified URL string.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload_value]
    # urlencode with doseq=True for list values; quote_via=str to keep
    # special chars readable in logs (scanner will re-encode on send)
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


# ─── Response comparison ──────────────────────────────────────────────────────

def compare_responses(
    baseline: ScanResult,
    probed:   ScanResult,
    payload:  Payload,
) -> dict:
    """
    Compare a baseline and payload response on four dimensions.

    Args:
        baseline: Clean response fetched before payload injection.
        probed:   Response fetched with payload injected into a parameter.
        payload:  The Payload object used for the probe.

    Returns:
        Dict with keys: status_changed, length_delta_pct, length_changed,
        sql_error_found, reflection_found.
    """
    b_body  = baseline.body or ""
    p_body  = probed.body   or ""

    status_changed = (baseline.status_code != probed.status_code)

    b_len = len(b_body)
    p_len = len(p_body)
    if b_len > 0:
        delta_pct = abs(p_len - b_len) / b_len
    else:
        delta_pct = 1.0 if p_len > 0 else 0.0

    length_changed = delta_pct > _LENGTH_CHANGE_THRESHOLD

    # SQL error detection (passive — checks response body only)
    sql_error = any(pat.search(p_body) for pat in _SQL_ERROR_PATTERNS)

    # Reflection detection: payload string appears verbatim in response body
    reflection = payload.value in p_body

    return {
        "status_changed":   status_changed,
        "length_delta_pct": round(delta_pct, 4),
        "length_changed":   length_changed,
        "sql_error_found":  sql_error,
        "reflection_found": reflection,
    }


# ─── PayloadTester ────────────────────────────────────────────────────────────

class PayloadTester:
    """
    Async-compatible payload testing engine.

    For each URL that contains query parameters, the tester:
      1. Fetches a baseline response.
      2. Iterates each parameter × each payload.
      3. Fetches the modified URL.
      4. Compares responses using compare_responses().
      5. Returns a UrlTestSummary with anomalous PayloadResults.

    The tester operates within the caller's Scanner session — it does not
    open its own connection pool.

    Args:
        config: Full settings dict (from utils.load_config).
    """

    def __init__(self, config: dict) -> None:
        self._cfg = _parse_config(config)
        self._sqli_payloads: list[Payload] = load_payloads(
            self._cfg.sqli_payload_file, "sqli"
        )
        self._xss_payloads: list[Payload] = load_payloads(
            self._cfg.xss_payload_file, "xss"
        )
        global _log
        _log = get_logger(__name__, config)
        _log.debug(
            "PayloadTester initialised: enabled=%s sqli=%d xss=%d",
            self._cfg.enabled,
            len(self._sqli_payloads),
            len(self._xss_payloads),
        )

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        """True if payload testing is enabled in config."""
        return self._cfg.enabled

    @property
    def payloads(self) -> list[Payload]:
        """All loaded payloads (sqli + xss)."""
        return self._sqli_payloads + self._xss_payloads

    async def test_url(
        self,
        scanner:  Scanner,
        url:      str,
        baseline: ScanResult | None = None,
    ) -> UrlTestSummary:
        """
        Run all payloads against each query parameter in *url*.

        If *baseline* is None, a clean GET is fetched first.
        URLs with no query parameters are returned with an empty summary.

        Args:
            scanner:  Open Scanner instance (shared session).
            url:      Target URL — must contain at least one query parameter
                      for any probes to be issued.
            baseline: Pre-fetched baseline ScanResult (optional).

        Returns:
            UrlTestSummary with anomalous PayloadResults.
        """
        if not self._cfg.enabled:
            _log.debug("Payload testing disabled — skipping %s", url)
            return UrlTestSummary(url=url, parameters_tested=[], total_probes=0)

        params = extract_query_params(url)
        if not params:
            _log.debug("No query parameters in %s — skipping payload tests", url)
            return UrlTestSummary(url=url, parameters_tested=[], total_probes=0)

        # Fetch baseline if not provided
        if baseline is None or not baseline.success:
            baseline = await scanner.get(url)
            if not baseline.success:
                _log.warning("Baseline fetch failed for %s — aborting payload tests", url)
                return UrlTestSummary(url=url, parameters_tested=[], total_probes=0)

        all_payloads = self.payloads
        anomalies: list[PayloadResult] = []
        total_probes = 0

        for param in params:
            for payload in all_payloads:
                probed_url = inject_payload(url, param, payload.value)
                probed     = await scanner.get(probed_url)
                total_probes += 1

                pr = self._build_result(url, param, payload, baseline, probed)
                if self._is_anomaly(pr):
                    anomalies.append(pr)
                    _log.info(
                        "Anomaly: %s param=%s payload=%r sql=%s reflect=%s",
                        url, param, payload.value[:20],
                        pr.sql_error_found, pr.reflection_found,
                    )

        summary = UrlTestSummary(
            url               = url,
            parameters_tested = params,
            total_probes      = total_probes,
            anomalies         = anomalies,
            sql_error_count   = sum(1 for a in anomalies if a.sql_error_found),
            reflection_count  = sum(1 for a in anomalies if a.reflection_found),
            status_change_count = sum(1 for a in anomalies if a.status_changed),
        )
        _log.info(
            "Payload test complete: %s — %d probes, %d anomalies",
            url, total_probes, len(anomalies),
        )
        return summary

    async def test_many(
        self,
        scanner: Scanner,
        urls:    list[str],
    ) -> list[UrlTestSummary]:
        """
        Run payload tests sequentially across a list of URLs.

        Sequential (not concurrent) to minimise target load and avoid
        race conditions on shared test state.

        Args:
            scanner: Open Scanner instance.
            urls:    List of target URLs.

        Returns:
            List of UrlTestSummary in the same order as *urls*.
        """
        results: list[UrlTestSummary] = []
        for url in urls:
            results.append(await self.test_url(scanner, url))
        return results

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_result(
        self,
        url:      str,
        param:    str,
        payload:  Payload,
        baseline: ScanResult,
        probed:   ScanResult,
    ) -> PayloadResult:
        """Build a PayloadResult from a baseline/probe response pair."""
        if probed.success:
            cmp = compare_responses(baseline, probed, payload)
            error = None
        else:
            cmp   = {
                "status_changed":   False,
                "length_delta_pct": 0.0,
                "length_changed":   False,
                "sql_error_found":  False,
                "reflection_found": False,
            }
            error = probed.error

        return PayloadResult(
            url              = url,
            parameter        = param,
            payload          = payload,
            baseline_status  = baseline.status_code,
            payload_status   = probed.status_code,
            baseline_length  = len(baseline.body or ""),
            payload_length   = len(probed.body   or ""),
            error            = error,
            **cmp,
        )

    @staticmethod
    def _is_anomaly(pr: PayloadResult) -> bool:
        """
        Return True if the PayloadResult shows any anomalous signal.

        An anomaly is any of:
        - SQL error signature detected in the response body.
        - Payload string reflected verbatim in the response body.
        - HTTP status code changed from baseline.
        - Content length changed by more than the threshold.
        """
        return (
            pr.sql_error_found
            or pr.reflection_found
            or pr.status_changed
            or pr.length_changed
        )
