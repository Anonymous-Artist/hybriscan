"""
core/pipeline.py
────────────────
End-to-end scan orchestrator for HybriScan.

Execution flow (Section V of the paper)
-----------------------------------------
  1. URL collection  — wordlist expansion + optional BFS crawl
  2. HTTP fetching   — async batch via Scanner
  3. Detection       — Detector.analyse_many() over all ScanResults
  4. Analysis        — Analyser.analyse_many() over all ScanResults
  5. Payload testing — PayloadTester.test_url() on parameterised URLs (opt-in)
  6. Scoring         — Scorer.score_many() merging Detection + Analysis
  7. Reporting       — Reporter.build() + Reporter.save()

The Pipeline class is the only external dependency of main.py.
All module coordination, error handling, and deduplication live here.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from core.analyzer import Analyser
from core.crawler import Crawler
from core.detector import Detector
from core.payload_tester import PayloadTester, UrlTestSummary
from core.reporter import Reporter, _now_iso
from core.scanner import Scanner, ScanResult
from core.scorer import Scorer, ScoringResult
from core.utils import get_logger, load_config, normalise_url

_log = get_logger(__name__)


# ─── Result container ─────────────────────────────────────────────────────────

@dataclass
class PipelineResult:
    """
    Complete output of one scan run.

    Attributes:
        target_url:      Normalised base URL that was scanned.
        scoring_results: Ordered list of ScoringResult (one per URL).
        payload_summaries: Payload test summaries keyed by URL.
        report:          Full report dict from Reporter.build().
        report_path:     Path to the saved JSON report file.
        started_at:      ISO-8601 scan start timestamp.
        finished_at:     ISO-8601 scan finish timestamp.
        urls_scanned:    Total unique URLs fetched.
        error:           Top-level error message if the scan aborted early.
    """
    target_url:        str
    scoring_results:   list[ScoringResult]       = field(default_factory=list)
    payload_summaries: dict[str, UrlTestSummary] = field(default_factory=dict)
    report:            dict                       = field(default_factory=dict)
    report_path:       Path | None                = None
    started_at:        str                        = ""
    finished_at:       str                        = ""
    urls_scanned:      int                        = 0
    error:             str | None                 = None


# ─── Pipeline ─────────────────────────────────────────────────────────────────

class Pipeline:
    """
    Async end-to-end scan pipeline.

    Instantiate once per scan run; not safe for concurrent reuse.

    Args:
        config:   Full settings dict (from utils.load_config).
        crawl:    Enable BFS link crawling from the target URL.
        depth:    Crawl depth override (applied to config before scanning).
        verbose:  Log per-endpoint score vectors to stdout.
    """

    def __init__(
        self,
        config:  dict,
        crawl:   bool = False,
        verbose: bool = False,
    ) -> None:
        self._config   = config
        self._crawl    = crawl
        self._verbose  = verbose

        # Instantiate all stateless modules
        self._detector = Detector(config)
        self._analyser = Analyser(config)
        self._scorer   = Scorer(config)
        self._reporter = Reporter(config)
        self._tester   = PayloadTester(config)

        global _log
        _log = get_logger(__name__, config)

    # ── Public API ────────────────────────────────────────────────────────────

    async def run(self, target_url: str) -> PipelineResult:
        """
        Execute the full scan pipeline against *target_url*.

        Args:
            target_url: Base URL to scan (scheme required).

        Returns:
            PipelineResult with all scan outputs populated.
        """
        target_url = normalise_url(target_url)
        started_at = _now_iso()
        result     = PipelineResult(target_url=target_url, started_at=started_at)

        _log.info("Scan started: %s", target_url)

        try:
            async with Scanner(self._config) as scanner:
                # ── 1. Collect URLs ──────────────────────────────────────────
                urls = await self._collect_urls(scanner, target_url)
                _log.info("URLs to scan: %d", len(urls))

                # ── 2. Fetch responses ───────────────────────────────────────
                scan_results = await self._fetch(scanner, urls)
                result.urls_scanned = len(scan_results)

                # ── 3 & 4. Detect + Analyse ──────────────────────────────────
                det_results = self._detector.analyse_many(scan_results)
                ana_results = self._analyser.analyse_many(scan_results)

                # ── 5. Payload testing (opt-in) ──────────────────────────────
                if self._tester.enabled:
                    result.payload_summaries = await self._run_payload_tests(
                        scanner, urls, scan_results
                    )

                # ── 6. Score ─────────────────────────────────────────────────
                pairs = list(zip(det_results, ana_results))
                scoring = self._scorer.score_many(pairs)
                result.scoring_results = scoring

                # ── 7. Report ────────────────────────────────────────────────
                result.finished_at = _now_iso()
                report      = self._reporter.build(
                    scoring, target_url,
                    started_at=started_at,
                    finished_at=result.finished_at,
                )
                report_path = self._reporter.save(report)
                result.report      = report
                result.report_path = report_path

        except Exception as exc:  # pragma: no cover
            result.error      = str(exc)
            result.finished_at = _now_iso()
            _log.error("Pipeline aborted: %s", exc, exc_info=True)

        _log.info(
            "Scan complete: %d URLs, %d vulnerable, report → %s",
            result.urls_scanned,
            sum(1 for r in result.scoring_results
                if r.label.value == "vulnerable"),
            result.report_path,
        )
        return result

    # ── Step implementations ──────────────────────────────────────────────────

    async def _collect_urls(self, scanner: Scanner, target_url: str) -> list[str]:
        """
        Build the ordered, deduplicated URL list for the scan.

        Steps:
          1. Start with the base URL.
          2. Expand against the admin/common wordlist paths.
          3. Optionally crawl for additional internal links.

        Returns a deduplicated list preserving first-seen order.
        """
        seen:  set[str]  = set()
        urls:  list[str] = []

        def _add(u: str) -> None:
            if u not in seen:
                seen.add(u)
                urls.append(u)

        # Base URL always first
        _add(target_url)

        # Wordlist expansion
        for path in self._wordlist_paths():
            _add(f"{target_url}/{path.lstrip('/')}")

        # Crawler
        if self._crawl:
            crawler = Crawler(self._config, target_url)
            pages   = await crawler.run(scanner)
            for page_url in Crawler.discovered_urls(pages):
                _add(page_url)
            _log.info("Crawler added %d URLs (total: %d)", len(pages), len(urls))

        return urls

    async def _fetch(
        self, scanner: Scanner, urls: list[str]
    ) -> list[ScanResult]:
        """
        Fetch all URLs concurrently via Scanner.scan_urls().

        Returns ScanResults in the same order as *urls*.
        """
        return await scanner.scan_urls(urls)

    async def _run_payload_tests(
        self,
        scanner:      Scanner,
        urls:         list[str],
        scan_results: list[ScanResult],
    ) -> dict[str, UrlTestSummary]:
        """
        Run payload tests on URLs that have query parameters and succeeded.

        Uses pre-fetched ScanResults as baselines to avoid re-fetching.

        Returns:
            Dict mapping URL → UrlTestSummary for tested URLs only.
        """
        summaries: dict[str, UrlTestSummary] = {}
        baseline_map = {r.url: r for r in scan_results if r.success}

        for url in urls:
            from core.payload_tester import extract_query_params
            if not extract_query_params(url):
                continue
            baseline = baseline_map.get(url)
            summary  = await self._tester.test_url(scanner, url, baseline)
            summaries[url] = summary

        return summaries

    def _wordlist_paths(self) -> list[str]:
        """
        Load admin + common paths from config wordlist files.

        Falls back to a minimal built-in list if files are missing.
        """
        wl_cfg   = self._config.get("wordlist", {})
        paths: list[str] = []

        for key in ("admin_paths", "common_paths"):
            filepath = wl_cfg.get(key, "")
            if filepath:
                fp = Path(filepath)
                if fp.exists():
                    with open(fp, encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                paths.append(line)

        if not paths:
            # Minimal built-in fallback — keeps scanning functional without
            # wordlist files and matches the paper's 27-endpoint test set.
            paths = [
                "admin", "admin/", "administrator", "login", "wp-admin",
                "wp-login.php", "phpmyadmin", ".env", ".git", "phpinfo.php",
                "server-status", "actuator", "config.php",
            ]
            _log.debug("Wordlist files not found — using built-in fallback (%d paths)",
                       len(paths))

        return paths


# ─── Summary printer ──────────────────────────────────────────────────────────

def print_summary(result: PipelineResult, verbose: bool = False) -> None:
    """
    Print a compact scan summary to stdout.

    Args:
        result:  Completed PipelineResult.
        verbose: If True, also print per-endpoint score vectors.
    """
    sep = "─" * 60
    print(f"\n{sep}")
    print(f"  HybriScan — Scan Summary")
    print(sep)
    print(f"  Target    : {result.target_url}")
    print(f"  Started   : {result.started_at}")
    print(f"  Finished  : {result.finished_at}")
    print(f"  Endpoints : {result.urls_scanned}")

    if result.error:
        print(f"  ERROR     : {result.error}")
        print(sep)
        return

    s = result.report.get("summary", {})
    print(f"  Vulnerable: {s.get('vulnerable_count', 0)}")
    print(f"  Benign    : {s.get('benign_count', 0)}")
    print(f"  Max score : {s.get('max_score', 0.0):.4f}")

    bd = s.get("severity_breakdown", {})
    print(f"\n  Severity breakdown:")
    for sev in ("critical", "high", "medium", "low", "none"):
        count = bd.get(sev, 0)
        if count:
            print(f"    {sev:<10}: {count}")

    top = s.get("top_findings", [])
    if top:
        print(f"\n  Top findings ({len(top)}):")
        for f in top[:5]:
            print(f"    [{f['severity']:<8}] {f['composite_score']:.4f}  {f['url']}")

    if result.report_path:
        print(f"\n  Report    : {result.report_path}")

    if verbose:
        print(f"\n  Per-endpoint scores:")
        for r in sorted(result.scoring_results,
                        key=lambda x: x.composite_score, reverse=True):
            print(f"    {r.composite_score:.4f}  [{r.severity.value:<8}]  {r.url}")
            if verbose and r.category_scores:
                cats = "  ".join(
                    f"{k}={v:.3f}"
                    for k, v in r.category_scores.items()
                    if v > 0
                )
                if cats:
                    print(f"           {cats}")

    print(sep)
