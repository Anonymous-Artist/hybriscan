"""
core/reporter.py
────────────────
Structured JSON report generator for HybriScan.

Responsibilities
----------------
- Accept a list of ScoringResult objects (one per scanned URL).
- Build a nested report dict with scan metadata, per-endpoint findings,
  and an aggregated risk summary.
- Serialise the report to a timestamped JSON file in the configured
  output directory.
- Provide a future-ready hook for HTML output (stub only in this phase).

Report schema (top-level keys)
-------------------------------
  meta          — scan identity, timestamp, configuration snapshot
  summary       — counts, severity breakdown, top findings
  endpoints     — per-URL findings list (ordered by composite score desc)
  risk_summary  — category-level aggregation across all endpoints

Integration
-----------
  reporter = Reporter(config)
  report   = reporter.build(scoring_results, target_url=args.url)
  path     = reporter.save(report)

This module performs NO scoring or detection logic.
"""

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.scorer import ScoringResult, Severity, Label
from core.detector import Category
from core.utils import get_logger

_log = get_logger(__name__)

_VERSION = "1.0.0"


# ─── Config ───────────────────────────────────────────────────────────────────

@dataclass
class ReporterConfig:
    """Typed view of settings.yaml[reporting]."""
    output_dir:           str  = "reports"
    fmt:                  str  = "json"
    include_score_vectors: bool = True
    include_timing:       bool  = True
    verbose:              bool  = False


def _parse_config(config: dict) -> ReporterConfig:
    rc = config.get("reporting", {})
    return ReporterConfig(
        output_dir            = str(rc.get("output_dir", "reports")).rstrip("/"),
        fmt                   = str(rc.get("format", "json")),
        include_score_vectors = bool(rc.get("include_score_vectors", True)),
        include_timing        = bool(rc.get("include_timing", True)),
        verbose               = bool(rc.get("verbose", False)),
    )


# ─── Schema builders (pure functions) ─────────────────────────────────────────

def _meta(target_url: str, n_scored: int, threshold: float,
          started_at: str, finished_at: str) -> dict[str, Any]:
    """Build the report `meta` block."""
    return {
        "hybriscan_version": _VERSION,
        "target_url":        target_url,
        "started_at":        started_at,
        "finished_at":       finished_at,
        "endpoints_scanned": n_scored,
        "threshold_used":    round(threshold, 4),
    }


def _endpoint_record(
    sr: ScoringResult,
    include_vectors: bool,
    include_timing:  bool,
) -> dict[str, Any]:
    """
    Serialise one ScoringResult into a flat endpoint record.

    Args:
        sr:              Scoring output for one URL.
        include_vectors: Whether to include per-category score dict.
        include_timing:  Whether to include request elapsed_ms.

    Returns:
        Dict suitable for JSON serialisation.
    """
    rec: dict[str, Any] = {
        "url":               sr.url,
        "status_code":       sr.detection_result.scan_result.status_code,
        "label":             sr.label.value,
        "severity":          sr.severity.value,
        "composite_score":   round(sr.composite_score, 4),
        "confidence":        round(sr.confidence, 4),
        "dominant_category": sr.dominant_category,
    }

    if include_vectors:
        rec["category_scores"]  = {k: round(v, 4) for k, v in sr.category_scores.items()}
        rec["analyser_bonuses"] = {k: round(v, 4) for k, v in sr.analyser_bonuses.items()}

    if include_timing:
        rec["elapsed_ms"] = sr.detection_result.scan_result.elapsed_ms

    # Matched evidence (descriptions only — no raw match text in default output)
    rec["evidence"] = [
        {"category": m.category, "description": m.description, "weight": round(m.weight, 3)}
        for m in sr.detection_result.matched_patterns
    ]

    # Security header gaps
    rec["missing_headers"]  = sr.analysis_result.headers.missing
    rec["insecure_headers"] = list(sr.analysis_result.headers.insecure_values.keys())

    # Form signals
    rec["forms"] = [
        {
            "action":                f.action,
            "method":               f.method,
            "has_password_field":   f.has_password_field,
            "action_path_suspicious": f.action_path_suspicious,
            "action_is_external":   f.action_is_external,
        }
        for f in sr.analysis_result.forms
    ]

    return rec


def _severity_breakdown(results: list[ScoringResult]) -> dict[str, int]:
    """Return count of endpoints at each severity level."""
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for r in results:
        counts[r.severity.value] += 1
    return counts


def _category_aggregation(results: list[ScoringResult]) -> dict[str, Any]:
    """
    For each detection category, compute:
    - max score observed across all endpoints
    - count of endpoints where that category was dominant
    - count of endpoints with any non-zero score for that category
    """
    agg: dict[str, Any] = {}
    for cat in Category:
        key = cat.value
        scores = [r.category_scores.get(key, 0.0) for r in results]
        agg[key] = {
            "max_score":       round(max(scores), 4) if scores else 0.0,
            "dominant_count":  sum(1 for r in results if r.dominant_category == key),
            "nonzero_count":   sum(1 for s in scores if s > 0.0),
        }
    return agg


def _top_findings(
    results: list[ScoringResult],
    n: int = 10,
) -> list[dict[str, Any]]:
    """
    Return the top-N VULNERABLE endpoints by composite score.

    Args:
        results: All ScoringResults for the scan.
        n:       Maximum number of findings to include.
    """
    flagged = [r for r in results if r.label == Label.VULNERABLE]
    flagged.sort(key=lambda r: r.composite_score, reverse=True)
    return [
        {
            "url":              r.url,
            "severity":         r.severity.value,
            "composite_score":  round(r.composite_score, 4),
            "dominant_category": r.dominant_category,
        }
        for r in flagged[:n]
    ]


def _summary(results: list[ScoringResult]) -> dict[str, Any]:
    """Build the report `summary` block."""
    n_total      = len(results)
    n_vulnerable = sum(1 for r in results if r.label == Label.VULNERABLE)
    n_benign     = n_total - n_vulnerable

    scores = [r.composite_score for r in results]
    avg_score = round(sum(scores) / n_total, 4) if n_total else 0.0
    max_score = round(max(scores), 4) if scores else 0.0

    return {
        "total_endpoints":     n_total,
        "vulnerable_count":    n_vulnerable,
        "benign_count":        n_benign,
        "average_score":       avg_score,
        "max_score":           max_score,
        "severity_breakdown":  _severity_breakdown(results),
        "top_findings":        _top_findings(results),
    }


def _risk_summary(results: list[ScoringResult]) -> dict[str, Any]:
    """Build the report `risk_summary` block (category-level aggregation)."""
    return {
        "category_aggregation": _category_aggregation(results),
        "missing_header_frequency": _header_frequency(results),
    }


def _header_frequency(results: list[ScoringResult]) -> dict[str, int]:
    """Count how many endpoints are missing each security header."""
    freq: dict[str, int] = {}
    for r in results:
        for h in r.analysis_result.headers.missing:
            freq[h] = freq.get(h, 0) + 1
    return dict(sorted(freq.items(), key=lambda x: x[1], reverse=True))


# ─── Reporter ─────────────────────────────────────────────────────────────────

class Reporter:
    """
    Builds and saves HybriScan JSON reports.

    Args:
        config: Full settings dict (from utils.load_config).
    """

    def __init__(self, config: dict) -> None:
        self._cfg = _parse_config(config)
        global _log
        _log = get_logger(__name__, config)
        _log.debug("Reporter initialised: output_dir=%s fmt=%s",
                   self._cfg.output_dir, self._cfg.fmt)

    # ── Public API ────────────────────────────────────────────────────────────

    def build(
        self,
        results:     list[ScoringResult],
        target_url:  str,
        started_at:  str | None = None,
        finished_at: str | None = None,
    ) -> dict[str, Any]:
        """
        Build the full report dict from a list of ScoringResults.

        Args:
            results:     All ScoringResult objects from Scorer.score_many().
            target_url:  The base URL passed to the scan (for metadata).
            started_at:  ISO-8601 scan start timestamp (auto-generated if None).
            finished_at: ISO-8601 scan finish timestamp (auto-generated if None).

        Returns:
            Nested report dict ready for JSON serialisation.
        """
        now       = _now_iso()
        started   = started_at  or now
        finished  = finished_at or now
        threshold = results[0].threshold_used if results else 0.0

        endpoints = sorted(
            [
                _endpoint_record(r, self._cfg.include_score_vectors,
                                    self._cfg.include_timing)
                for r in results
            ],
            key=lambda e: e["composite_score"],
            reverse=True,
        )

        report: dict[str, Any] = {
            "meta":         _meta(target_url, len(results), threshold,
                                  started, finished),
            "summary":      _summary(results),
            "endpoints":    endpoints,
            "risk_summary": _risk_summary(results),
        }

        _log.info(
            "Report built: %d endpoints, %d vulnerable.",
            len(results),
            report["summary"]["vulnerable_count"],
        )
        return report

    def save(self, report: dict[str, Any], filename: str | None = None) -> Path:
        """
        Serialise the report dict to a JSON file.

        The file is written to the configured output_dir.  If no filename is
        provided, one is generated from the target URL slug and a timestamp.

        Args:
            report:   Report dict from Reporter.build().
            filename: Override filename (without directory prefix).

        Returns:
            Path to the written report file.
        """
        out_dir = Path(self._cfg.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        if not filename:
            slug      = _url_slug(report["meta"].get("target_url", "unknown"))
            timestamp = report["meta"].get("finished_at", _now_iso())[:19].replace(":", "-")
            filename  = f"hybriscan_{slug}_{timestamp}.json"

        path = out_dir / filename
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        _log.info("Report saved: %s", path)
        return path

    def to_json(self, report: dict[str, Any]) -> str:
        """
        Return the report as a formatted JSON string (no file I/O).

        Useful for piping output or embedding in larger workflows.

        Args:
            report: Report dict from Reporter.build().
        """
        return json.dumps(report, indent=2, ensure_ascii=False)

    # ── Future hook ───────────────────────────────────────────────────────────

    def to_html(self, report: dict[str, Any]) -> str:  # pragma: no cover
        """
        HTML report rendering (Phase 10 placeholder).

        Raises NotImplementedError until a template engine is wired.
        """
        raise NotImplementedError("HTML reporting is planned for Phase 10.")


# ─── Utilities ────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _url_slug(url: str) -> str:
    """
    Convert a URL into a filesystem-safe slug for report filenames.

    Example: "http://target.local:8080" → "target.local_8080"
    """
    from urllib.parse import urlparse
    p = urlparse(url)
    host = p.netloc or p.path
    slug = host.replace(":", "_").replace("/", "_").strip("_")
    return slug or "scan"
