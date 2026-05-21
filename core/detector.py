"""
core/detector.py
────────────────
Vulnerability detection engine for HybriScan.

Implements the Pattern Detection Engine described in Section V-C of the
HybriScan paper (Suthar, Gupta, Solanki, 2024).

Architecture
------------
Six detection categories are defined, each as an independent PatternBank.
A PatternBank is a list of (compiled_regex, weight, description) tuples.
Pattern weights reflect discriminative specificity per Section VI-D:

  - High weight (0.75–1.00): patterns that appear almost exclusively in
    the presence of a true vulnerability (e.g. MySQL error strings,
    "Index of /" in a page title).
  - Medium weight (0.40–0.74): patterns reliably associated with a
    category but occasionally present in benign content.
  - Low weight (0.10–0.39): broad heuristics that contribute evidence
    only in combination (e.g. the substring "admin" in a URL segment).

Detection categories
--------------------
  ADMIN        — Exposed administrative interfaces
  SQLI         — SQL injection error indicators
  LOGIN        — Authentication endpoint exposure
  DIR_LISTING  — Directory listing misconfigurations
  XSS          — Reflected XSS surface indicators
  SENSITIVE    — Sensitive file / path exposure

Each category maps directly to the paper's OWASP 2021 threat model
(Section III-C): A01 Broken Access Control, A03 Injection, A05 Security
Misconfiguration, A07 Auth Failures.

Usage
-----
    from core.detector import Detector, DetectionResult
    from core.scanner import ScanResult

    detector = Detector(config)
    result   = detector.analyse(scan_result)
    # result.category_scores  → dict[str, float]  normalised [0, 1]
    # result.composite_score  → float              max-pool across categories
    # result.matched_patterns → dict[str, list]    evidence per category
"""

import re
from dataclasses import dataclass, field
from enum import Enum

from core.scanner import ScanResult
from core.utils import get_logger

_log = get_logger(__name__)

# ─── Category Enum ────────────────────────────────────────────────────────────

class Category(str, Enum):
    """Vulnerability detection categories aligned with the paper's threat model."""
    ADMIN       = "admin"
    SQLI        = "sqli"
    LOGIN       = "login"
    DIR_LISTING = "dir_listing"
    XSS         = "xss"
    SENSITIVE   = "sensitive"


# ─── Pattern Bank Types ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class Pattern:
    """
    A single detection rule: compiled regex + weight + human description.

    Args:
        regex:       Compiled regular expression (IGNORECASE | MULTILINE).
        weight:      Contribution to raw category score on match (0.0–1.0).
        description: Short human-readable label for report evidence strings.
    """
    regex: re.Pattern
    weight: float
    description: str


# Convenience alias — a bank is an ordered list of Patterns for one category.
PatternBank = list[Pattern]


def _p(pattern: str, weight: float, description: str) -> Pattern:
    """Compile and wrap a regex pattern into a Pattern namedtuple."""
    return Pattern(
        regex=re.compile(pattern, re.IGNORECASE | re.MULTILINE),
        weight=weight,
        description=description,
    )


# ─── Pattern Banks ────────────────────────────────────────────────────────────
# Each bank is defined as a module-level constant — compiled once at import
# time, shared across all Detector instances.  This matches Algorithm 1 of
# the paper (pattern_banks dict, compiled regexes, weight tuples).

# ── Admin Panel Detection ─────────────────────────────────────────────────────
# OWASP A01 — Broken Access Control
# High-weight patterns match paths / body markers unique to admin surfaces.
# Low-weight patterns (e.g. bare "admin") require corroboration.

ADMIN_PATTERNS: PatternBank = [
    # URL-level indicators
    _p(r"/wp-admin(?:/|$)",                   0.95, "WordPress admin path"),
    _p(r"/administrator(?:/|$)",              0.90, "Joomla /administrator path"),
    _p(r"/admin(?:istrat(?:ion|or))?(?:/|$)", 0.70, "Generic /admin path"),
    _p(r"/phpmyadmin(?:/|$)",                 0.95, "phpMyAdmin path"),
    _p(r"/adminer(?:\.php)?(?:/|$)",          0.90, "Adminer DB tool path"),
    _p(r"/controlpanel(?:/|$)",               0.75, "Control panel path"),
    _p(r"/cpanel(?:/|$)",                     0.80, "cPanel path"),
    _p(r"/webadmin(?:/|$)",                   0.75, "Web admin path"),
    _p(r"/siteadmin(?:/|$)",                  0.75, "Site admin path"),
    _p(r"/adminpanel(?:/|$)",                 0.80, "Admin panel path"),
    # Body / title indicators
    _p(r"<title>[^<]*admin(?:istrat(?:ion|or))?[^<]*</title>",
                                              0.80, "Admin keyword in page title"),
    _p(r"admin(?:istration)?\s+(?:panel|console|dashboard|portal)",
                                              0.70, "Admin panel/console phrasing in body"),
    _p(r"(?:dashboard|control\s+panel).*(?:logout|sign\s*out)",
                                              0.65, "Dashboard with logout link"),
    _p(r"<(?:h[1-3]|title)[^>]*>[^<]*(?:admin|dashboard)[^<]*</(?:h[1-3]|title)>",
                                              0.60, "Admin/dashboard in heading"),
    # Broad heuristic — low weight, valid only in combination
    _p(r"\badmin\b",                          0.20, "Bare 'admin' keyword"),
]

# ── SQL Injection Indicators ──────────────────────────────────────────────────
# OWASP A03 — Injection
# Focuses on error message leakage (detectable without active payloads).
# Active payload testing is Phase 8; these are passive indicators only.

SQLI_PATTERNS: PatternBank = [
    # MySQL error strings — very high specificity
    _p(r"you have an error in your sql syntax",         0.95, "MySQL syntax error"),
    _p(r"warning:\s*mysql_",                            0.90, "PHP MySQL warning"),
    _p(r"unclosed quotation mark after the character string",
                                                        0.90, "MSSQL unclosed quote error"),
    _p(r"quoted string not properly terminated",        0.85, "Oracle quoted string error"),
    _p(r"pg_query\(\).*error",                          0.85, "PostgreSQL pg_query error"),
    _p(r"supplied argument is not a valid mysql result resource",
                                                        0.85, "PHP MySQL resource error"),
    _p(r"ORA-\d{5}:",                                   0.90, "Oracle ORA- error code"),
    _p(r"microsoft sql server.*error",                  0.85, "MSSQL server error string"),
    _p(r"sqlite_(?:exception|error)",                   0.80, "SQLite error"),
    _p(r"(?:syntax error|sql error|sql syntax)[^.]{0,80}(?:query|statement)",
                                                        0.75, "Generic SQL error with query context"),
    # Stack-trace / debug leakage that implies SQLi surface
    _p(r"(?:mysql|pgsql|sqlite|mssql|oracle).*exception",
                                                        0.70, "Database exception in body"),
    _p(r"db_query\s*\(",                                0.55, "Raw db_query() call exposed"),
    # URL-level SQLi surface indicators (query parameters with SQL tokens)
    _p(r"[?&][^=]+=(?:['\"]|--|\bunion\b|\bselect\b|\bor\b\s+\d)",
                                                        0.60, "SQL token in query parameter"),
    _p(r"\bUNION(?:\s|\+)+(?:ALL(?:\s|\+)+)?SELECT\b",        0.75, "UNION SELECT in URL/body"),
]

# ── Login Page Detection ──────────────────────────────────────────────────────
# OWASP A07 — Identification and Authentication Failures
# Detects authentication endpoints as potential brute-force surfaces.

LOGIN_PATTERNS: PatternBank = [
    # URL-level indicators
    _p(r"/(?:login|log-in)(?:[/?#]|$|\s)",             0.85, "Login path in URL"),
    _p(r"/(?:signin|sign-in)(?:[/?#]|$|\s)",           0.85, "Signin path in URL"),
    _p(r"/(?:auth(?:enticate)?|session/new)(?:[/?#]|$|\s)", 0.75, "Auth/session path in URL"),
    _p(r"/(?:account/signin|user/login)(?:[/?#]|$|\s)",0.80, "Account login path"),
    _p(r"/wp-login\.php(?:[?#]|$|\s)",                 0.90, "WordPress login path"),
    # Body — form markup indicators (high specificity)
    _p(r"<input[^>]+(?:type=[\"']password[\"']|name=[\"']password[\"'])[^>]*>",
                                                        0.90, "Password input field in body"),
    _p(r"<form[^>]+(?:action=[\"'][^\"']*(?:login|auth|signin)[\"'])[^>]*>",
                                                        0.85, "Form action points to login endpoint"),
    _p(r"<input[^>]+name=[\"'](?:username|user|email|uname)[\"'][^>]*>",
                                                        0.70, "Username/email input field"),
    _p(r"(?:forgot\s+(?:your\s+)?password|reset\s+password)",
                                                        0.60, "Password reset link in body"),
    # Title / heading indicators
    _p(r"<title>[^<]*(?:login|sign[\s-]?in|log[\s-]?in)[^<]*</title>",
                                                        0.80, "Login keyword in page title"),
    _p(r"<(?:h[1-3])[^>]*>[^<]*(?:login|sign\s*in)[^<]*</h[1-3]>",
                                                        0.65, "Login keyword in page heading"),
]

# ── Directory Listing Detection ───────────────────────────────────────────────
# OWASP A05 — Security Misconfiguration
# Apache/Nginx directory index pages have highly distinctive markers.

DIR_LISTING_PATTERNS: PatternBank = [
    # Title-level markers — maximum specificity
    _p(r"<title>\s*Index of\s+/",                      1.00, "'Index of /' in page title"),
    _p(r"<title>\s*Directory listing",                  0.95, "'Directory listing' in title"),
    # Body structure markers
    _p(r"<a\s+href=[\"']\.\.[\"']>\s*Parent Directory",0.95, "Parent Directory link"),
    _p(r"(?:Apache|Nginx)\s+Server\s+at\s+\S+\s+Port", 0.80, "Apache/Nginx server signature"),
    _p(r"<h1>\s*Index of\s+/",                         0.95, "'Index of /' in H1"),
    _p(r"Last modified.*Size.*Description",             0.85, "Directory index column headers"),
    _p(r"<hr>\s*<address>.*Server at",                 0.80, "Apache directory footer pattern"),
    _p(r"\[DIR\]|\[PARENTDIR\]",                        0.75, "Directory marker in index body"),
]

# ── XSS Surface Indicators ────────────────────────────────────────────────────
# OWASP A03 — Injection (Cross-site Scripting)
# Passive indicators of reflective XSS surfaces — no active payload injection.
# These patterns identify structural characteristics, not confirmed exploits.

XSS_PATTERNS: PatternBank = [
    # URL-level: unencoded or suspicious query parameter values
    _p(r"[?&][^=]+=<[a-z]",                            0.80, "HTML tag injected in query parameter"),
    _p(r"[?&][^=]+=.*%3C(?:script|img|svg|iframe)",    0.75, "URL-encoded HTML tag in param"),
    _p(r"[?&][^=]+=.*javascript:",                      0.75, "javascript: URI in query parameter"),
    _p(r"[?&][^=]+=.*(?:onerror|onload|onclick)\s*=",  0.80, "Event handler in query parameter"),
    # Body: reflection of dangerous patterns (inline scripts near user-input context)
    _p(r"<script[^>]*>\s*(?:alert|confirm|prompt)\s*\(", 0.70, "Inline alert/confirm/prompt script"),
    _p(r"document\.(?:cookie|location|write)\s*=",     0.65, "DOM sink assignment in body"),
    _p(r"innerHTML\s*=\s*['\"]?<",                     0.65, "innerHTML assigned HTML literal"),
    # Input fields that echo query parameters without apparent encoding
    _p(r"<input[^>]+value=['\"][^'\"]*(?:<|%3C)[^'\"]*['\"]",
                                                        0.75, "Unescaped angle bracket in input value"),
    # Error pages that reflect user input
    _p(r"(?:not found|error)[^<]{0,100}<(?:b|strong|code)[^>]*>[^<]{0,80}(?:<|%3C)",
                                                        0.50, "Reflected content in error message"),
]

# ── Sensitive File / Path Detection ──────────────────────────────────────────
# OWASP A05 — Security Misconfiguration
# Paths and content markers associated with exposed sensitive resources.

SENSITIVE_PATTERNS: PatternBank = [
    # URL-level: high-specificity sensitive paths
    _p(r"/\.env(?:\b|$)",                              0.95, ".env file path"),
    _p(r"/\.git(?:/|$)",                               0.90, ".git directory path"),
    _p(r"/\.svn(?:/|$)",                               0.85, ".svn directory path"),
    _p(r"/(?:wp-config\.php|settings\.php|database\.php)(?:\b|$)",
                                                        0.95, "CMS configuration file path"),
    _p(r"/(?:phpinfo|info|test|debug)\.php(?:\b|$)",   0.90, "PHP diagnostic file path"),
    _p(r"/(?:server-status|server-info)(?:\b|$)",      0.85, "Apache server-status path"),
    _p(r"/(?:actuator|health|metrics)(?:/|$)",          0.80, "Actuator endpoint path"),
    # Body-level: content markers from exposed sensitive files
    _p(r"DB_PASSWORD\s*=",                             0.95, "DB_PASSWORD in body (.env leak)"),
    _p(r"APP_(?:KEY|SECRET|TOKEN)\s*=",                0.90, "APP_KEY/SECRET in body"),
    _p(r"phpinfo\(\)",                                 0.90, "phpinfo() call in body"),
    _p(r"\[mysqld\]|\[client\]",                       0.85, "MySQL config section in body"),
]

# ── Master Registry ────────────────────────────────────────────────────────────
# Maps each Category to its PatternBank and theoretical max score.
# max_score = sum of all weights in the bank (used for normalisation).

_BANKS: dict[Category, PatternBank] = {
    Category.ADMIN:       ADMIN_PATTERNS,
    Category.SQLI:        SQLI_PATTERNS,
    Category.LOGIN:       LOGIN_PATTERNS,
    Category.DIR_LISTING: DIR_LISTING_PATTERNS,
    Category.XSS:         XSS_PATTERNS,
    Category.SENSITIVE:   SENSITIVE_PATTERNS,
}

_MAX_SCORES: dict[Category, float] = {
    cat: sum(p.weight for p in bank)
    for cat, bank in _BANKS.items()
}


# ─── Result Types ─────────────────────────────────────────────────────────────

@dataclass
class PatternMatch:
    """
    Record of a single pattern that fired during detection.

    Stored in DetectionResult.matched_patterns for evidence and
    report generation in Phase 7.
    """
    category: str
    description: str
    weight: float
    match_text: str          # first 120 chars of matched text (for report evidence)


@dataclass
class DetectionResult:
    """
    Full detection output for one URL.

    Produced by Detector.analyse() and consumed by scorer.py (Phase 6)
    and reporter.py (Phase 7).

    Attributes:
        url:              The scanned URL.
        category_scores:  Normalised score [0.0, 1.0] per category.
        composite_score:  Max-pool across category_scores (Algorithm 1).
        dominant_category: Category with the highest normalised score.
        matched_patterns: Evidence list — patterns that fired, per category.
        scan_result:      Original ScanResult (headers, status, timing).
    """
    url: str
    category_scores:   dict[str, float]
    composite_score:   float
    dominant_category: str | None
    matched_patterns:  list[PatternMatch]
    scan_result:       ScanResult


# ─── Detector ─────────────────────────────────────────────────────────────────

class Detector:
    """
    Stateless vulnerability detection engine.

    Implements Algorithm 1 (ComputeVulnerabilityScore) from the paper.
    For each URL + response body pair, the engine:

    1. Concatenates the URL and response body into a single search string.
    2. Iterates each PatternBank, accumulating a raw score from weight-
       weighted match counts (capped at 1 match per pattern to prevent
       a single repetitive pattern from dominating the score).
    3. Normalises each raw score to [0, 1] by dividing by the bank's
       theoretical maximum score.
    4. Applies a category-level multiplier from config (default 1.0,
       reserved for future ML override of per-category sensitivity).
    5. Returns raw scores, normalised scores, composite score, and
       matched pattern evidence in a DetectionResult.

    The Detector is stateless — it holds no per-scan state and is safe
    to share across concurrent coroutines.

    Args:
        config: Full settings dict (from utils.load_config).
    """

    def __init__(self, config: dict) -> None:
        # Category-level weight multipliers from settings.yaml[detection]
        detection_cfg = config.get("detection", {})
        category_weights = detection_cfg.get("category_weights", {})

        self._multipliers: dict[Category, float] = {
            cat: float(category_weights.get(cat.value, 1.0))
            for cat in Category
        }

        global _log
        _log = get_logger(__name__, config)
        _log.debug("Detector initialised with %d categories", len(_BANKS))

    # ── Public API ────────────────────────────────────────────────────────────

    def analyse(self, scan_result: ScanResult) -> DetectionResult:
        """
        Run all pattern banks against a single ScanResult.

        Only called for successful HTTP responses (status_code is not None).
        For failed requests, a zero-score DetectionResult is returned
        without running any patterns.

        Args:
            scan_result: Populated ScanResult from Scanner.get().

        Returns:
            DetectionResult with per-category scores and matched evidence.
        """
        if not scan_result.success:
            _log.debug("Skipping detection for failed request: %s", scan_result.url)
            return self._empty_result(scan_result)

        # Build combined search target: URL + space + response body
        search_target = f"{scan_result.url} {scan_result.body}"

        category_scores: dict[str, float] = {}
        all_matches:     list[PatternMatch] = []

        for category, bank in _BANKS.items():
            norm_score, matches = self._score_bank(
                category, bank, search_target
            )
            # Apply category-level multiplier, clamp to [0, 1]
            adjusted = min(1.0, norm_score * self._multipliers[category])
            category_scores[category.value] = round(adjusted, 6)
            all_matches.extend(matches)

        # Composite score: maximum normalised category score (Algorithm 1)
        composite = max(category_scores.values()) if category_scores else 0.0

        # Identify the category driving the composite score
        dominant = max(category_scores, key=lambda k: category_scores[k]) \
                   if composite > 0.0 else None

        _log.debug(
            "%s → composite=%.4f dominant=%s",
            scan_result.url, composite, dominant,
        )

        return DetectionResult(
            url              = scan_result.url,
            category_scores  = category_scores,
            composite_score  = round(composite, 6),
            dominant_category= dominant,
            matched_patterns = all_matches,
            scan_result      = scan_result,
        )

    def analyse_many(self, scan_results: list[ScanResult]) -> list[DetectionResult]:
        """
        Run detection across a list of ScanResults (synchronous batch).

        Suitable for post-crawl batch analysis where all HTTP responses
        are already collected.  For streaming analysis during a live scan,
        call analyse() per result inside an async loop.

        Args:
            scan_results: List of ScanResult objects from Scanner.scan_urls()
                          or Crawler.run().

        Returns:
            List of DetectionResult in the same order as input.
        """
        results = [self.analyse(r) for r in scan_results]
        flagged = sum(1 for r in results if r.composite_score > 0.0)
        _log.info(
            "Batch detection complete: %d/%d URLs produced non-zero scores.",
            flagged, len(results),
        )
        return results

    # ── Internal ──────────────────────────────────────────────────────────────

    def _score_bank(
        self,
        category: Category,
        bank: PatternBank,
        target: str,
    ) -> tuple[float, list[PatternMatch]]:
        """
        Score one PatternBank against the combined URL + body string.

        Per Algorithm 1:
          raw_score += min(match_count, 1) * weight   (binary match contribution)
          norm_score  = min(1.0, raw_score / max_score)

        Using min(match_count, 1) ensures each pattern contributes at most
        its weight once, preventing repeated occurrences of a low-specificity
        pattern from inflating the score.

        Args:
            category: Category enum value (for PatternMatch labelling).
            bank:     List of Pattern tuples for this category.
            target:   Concatenated URL + response body string.

        Returns:
            Tuple of (normalised_score, list_of_PatternMatch).
        """
        raw_score: float      = 0.0
        matches:   list[PatternMatch] = []
        max_score: float      = _MAX_SCORES[category]

        for pattern in bank:
            found = pattern.regex.search(target)
            if found:
                raw_score += pattern.weight
                matches.append(PatternMatch(
                    category   = category.value,
                    description= pattern.description,
                    weight     = pattern.weight,
                    match_text = target[
                        max(0, found.start() - 10) :
                        min(len(target), found.end() + 30)
                    ][:120],
                ))

        norm_score = min(1.0, raw_score / max_score) if max_score > 0 else 0.0
        return norm_score, matches

    @staticmethod
    def _empty_result(scan_result: ScanResult) -> DetectionResult:
        """Return a zero-score DetectionResult for a failed HTTP request."""
        return DetectionResult(
            url              = scan_result.url,
            category_scores  = {cat.value: 0.0 for cat in Category},
            composite_score  = 0.0,
            dominant_category= None,
            matched_patterns = [],
            scan_result      = scan_result,
        )
