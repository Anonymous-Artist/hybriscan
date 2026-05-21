"""
core/analyzer.py
────────────────
Structured HTML and HTTP response analyser for HybriScan.

Responsibilities
----------------
- Parse the HTTP response body and headers from a ScanResult.
- Extract structured metadata consumed by scorer.py (Phase 6) and
  reporter.py (Phase 7) without performing scoring decisions.
- Provide five independent analysis sub-modules:
    1. TitleAnalyser    — <title> tag extraction and keyword flags
    2. FormAnalyser     — form enumeration, field classification, action risk
    3. HeaderAnalyser   — HTTP security header presence/value audit
    4. ScriptAnalyser   — inline <script> risk pattern detection
    5. KeywordAnalyser  — suspicious term extraction from visible text

Integration
-----------
Analyser.analyse(scan_result) returns an AnalysisResult dataclass.
The scorer (Phase 6) merges AnalysisResult with DetectionResult to compute
the final weighted composite score.

This module performs NO scoring and makes NO classification decisions.
"""

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Tag

from core.scanner import ScanResult
from core.utils import get_logger

_log = get_logger(__name__)

# ─── Security Header Constants ────────────────────────────────────────────────

SECURITY_HEADERS: tuple[str, ...] = (
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",           # legacy but still observed in the wild
)

# ─── Compiled Patterns ────────────────────────────────────────────────────────

# Suspicious inline JS — passive indicators only, no exploit logic
_JS_SUSPICIOUS: tuple[re.Pattern, ...] = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"document\.cookie",
    r"document\.location\s*=",
    r"window\.location\s*=",
    r"eval\s*\(",
    r"innerHTML\s*=",
    r"(?:alert|confirm|prompt)\s*\(",
    r"atob\s*\(",                  # base64 decode — common obfuscation step
    r"String\.fromCharCode\s*\(",  # char-code obfuscation
    r"(?:fetch|XMLHttpRequest)\s*\(",  # async exfil patterns
))

# Keywords in visible body text that raise contextual suspicion
_SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "sql", "error", "exception", "traceback", "stack trace",
    "debug", "password", "secret", "token", "api_key",
    "root", "administrator", "privilege", "access denied",
    "index of", "parent directory",
)


# ─── Sub-Result Dataclasses ───────────────────────────────────────────────────

@dataclass
class TitleInfo:
    """Parsed page title metadata."""
    raw: str                         # full <title> text or empty string
    lower: str                       # lower-cased for keyword matching
    has_admin_keyword: bool   = False
    has_login_keyword: bool   = False
    has_error_keyword: bool   = False
    has_index_keyword: bool   = False  # "index of" — directory listing signal


@dataclass
class FormField:
    """A single <input>, <select>, or <textarea> element inside a form."""
    tag: str                         # "input", "select", "textarea"
    name: str                        # name attribute or ""
    field_type: str                  # type attribute (inputs) or tag name
    value: str                       # value attribute or ""
    is_hidden: bool   = False
    is_password: bool = False
    is_sensitive_name: bool = False  # name suggests sensitive data


@dataclass
class FormInfo:
    """Analysis of a single <form> element."""
    action: str                      # form action attribute
    method: str                      # GET / POST / ""
    has_password_field: bool  = False
    has_username_field: bool  = False
    has_hidden_fields: bool   = False
    action_is_external: bool  = False
    action_path_suspicious: bool = False   # action contains login/admin/auth
    fields: list[FormField]          = field(default_factory=list)


@dataclass
class HeaderAudit:
    """Security header presence and raw values."""
    present: dict[str, str]          = field(default_factory=dict)  # header → value
    missing: list[str]               = field(default_factory=list)  # expected but absent
    insecure_values: dict[str, str]  = field(default_factory=dict)  # header → reason


@dataclass
class ScriptInfo:
    """Inline <script> block analysis summary."""
    total_inline_scripts: int        = 0
    suspicious_pattern_hits: list[str] = field(default_factory=list)  # pattern descriptions


@dataclass
class KeywordInfo:
    """Visible-text keyword extraction summary."""
    found: list[str]                 = field(default_factory=list)   # matched keywords
    snippet_map: dict[str, str]      = field(default_factory=dict)   # keyword → 80-char context


@dataclass
class AnalysisResult:
    """
    Complete structured analysis of one HTTP response.

    Produced by Analyser.analyse() and passed to scorer.py alongside
    DetectionResult.  All fields represent observed facts — no scoring
    thresholds or classification labels are set here.

    Attributes:
        url:        The scanned URL.
        status_code: HTTP status code (None on network error).
        title:      Parsed page title metadata.
        forms:      List of FormInfo for every <form> on the page.
        headers:    Security header audit.
        scripts:    Inline script analysis.
        keywords:   Suspicious keyword extraction.
        meta_charset: charset from <meta charset> or Content-Type header.
        word_count: Approximate visible word count in the body.
    """
    url: str
    status_code: int | None
    title: TitleInfo
    forms: list[FormInfo]            = field(default_factory=list)
    headers: HeaderAudit             = field(default_factory=HeaderAudit)
    scripts: ScriptInfo              = field(default_factory=ScriptInfo)
    keywords: KeywordInfo            = field(default_factory=KeywordInfo)
    meta_charset: str                = ""
    word_count: int                  = 0


# ─── Sub-Analysers ────────────────────────────────────────────────────────────

class TitleAnalyser:
    """Extract and flag <title> content."""

    _ADMIN  = re.compile(r"\badmin(?:istrat(?:or|ion))?\b", re.I)
    _LOGIN  = re.compile(r"\b(?:login|sign[\s-]?in|log[\s-]?in)\b", re.I)
    _ERROR  = re.compile(r"\b(?:error|exception|not found|forbidden)\b", re.I)
    _INDEX  = re.compile(r"\bindex\s+of\b", re.I)

    def analyse(self, soup: BeautifulSoup) -> TitleInfo:
        """
        Return TitleInfo from the parsed document.

        Args:
            soup: BeautifulSoup-parsed document.
        """
        tag = soup.find("title")
        raw = tag.get_text(strip=True) if isinstance(tag, Tag) else ""
        lo  = raw.lower()
        return TitleInfo(
            raw=raw,
            lower=lo,
            has_admin_keyword=bool(self._ADMIN.search(raw)),
            has_login_keyword=bool(self._LOGIN.search(raw)),
            has_error_keyword=bool(self._ERROR.search(raw)),
            has_index_keyword=bool(self._INDEX.search(raw)),
        )


class FormAnalyser:
    """Enumerate forms and classify their fields and actions."""

    _SENSITIVE_NAMES = re.compile(
        r"\b(?:password|passwd|pass|secret|token|api[_-]?key|credit[_-]?card|ssn|cvv)\b",
        re.I,
    )
    _SUSPICIOUS_ACTION = re.compile(
        r"/(?:admin|login|signin|auth|authenticate|dashboard|panel)", re.I
    )
    _USERNAME_NAMES = re.compile(
        r"\b(?:user(?:name)?|email|uname|login|uid)\b", re.I
    )

    def analyse(self, soup: BeautifulSoup, page_url: str) -> list[FormInfo]:
        """
        Return a FormInfo for every <form> tag in the document.

        Args:
            soup:     Parsed document.
            page_url: Absolute URL of the page (for external-action detection).
        """
        page_origin = self._origin(page_url)
        forms: list[FormInfo] = []

        for form_tag in soup.find_all("form"):
            if not isinstance(form_tag, Tag):
                continue

            action = str(form_tag.get("action") or "").strip()
            method = str(form_tag.get("method") or "").upper()

            action_is_external = bool(
                action.startswith("http") and
                self._origin(action) != page_origin
            )
            action_suspicious = bool(self._SUSPICIOUS_ACTION.search(action))

            fields: list[FormField] = []
            has_password = has_username = has_hidden = False

            for el in form_tag.find_all(["input", "select", "textarea"]):
                if not isinstance(el, Tag):
                    continue
                ff = self._classify_field(el)
                fields.append(ff)
                if ff.is_password:
                    has_password = True
                if self._USERNAME_NAMES.search(ff.name):
                    has_username = True
                if ff.is_hidden:
                    has_hidden = True

            forms.append(FormInfo(
                action=action,
                method=method,
                has_password_field=has_password,
                has_username_field=has_username,
                has_hidden_fields=has_hidden,
                action_is_external=action_is_external,
                action_path_suspicious=action_suspicious,
                fields=fields,
            ))

        return forms

    def _classify_field(self, el: Tag) -> FormField:
        name       = str(el.get("name") or "")
        field_type = str(el.get("type") or el.name or "").lower()
        value      = str(el.get("value") or "")
        is_hidden  = field_type == "hidden"
        is_password = field_type == "password"
        is_sensitive = bool(self._SENSITIVE_NAMES.search(name))
        return FormField(
            tag=el.name,
            name=name,
            field_type=field_type,
            value=value,
            is_hidden=is_hidden,
            is_password=is_password,
            is_sensitive_name=is_sensitive,
        )

    @staticmethod
    def _origin(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}" if p.netloc else ""


class HeaderAnalyser:
    """
    Audit HTTP response headers for security controls.

    Checks presence of the canonical set of security headers defined in
    SECURITY_HEADERS and flags known insecure value patterns.
    """

    # Patterns for known insecure header values
    _INSECURE: dict[str, tuple[re.Pattern, str]] = {
        "x-frame-options": (
            re.compile(r"^allow-from", re.I),
            "ALLOW-FROM is deprecated and not supported by modern browsers",
        ),
        "x-xss-protection": (
            re.compile(r"^1$", re.I),
            "x-xss-protection: 1 without mode=block provides partial protection only",
        ),
        "content-security-policy": (
            re.compile(r"unsafe-(?:inline|eval)", re.I),
            "CSP contains unsafe-inline or unsafe-eval — reduces XSS mitigation",
        ),
        "strict-transport-security": (
            re.compile(r"max-age\s*=\s*[0-9]{1,5}(?:[^0-9]|$)", re.I),
            "HSTS max-age is very short (< 100000s) — reduces effective protection",
        ),
    }

    def analyse(self, headers: dict[str, str]) -> HeaderAudit:
        """
        Return a HeaderAudit from the response headers dict.

        Args:
            headers: Response headers with lower-cased keys
                     (as produced by Scanner._attempt_get).
        """
        present: dict[str, str] = {}
        missing: list[str] = []
        insecure: dict[str, str] = {}

        for header in SECURITY_HEADERS:
            value = headers.get(header, "")
            if value:
                present[header] = value
                # Check for known insecure value patterns
                if header in self._INSECURE:
                    pattern, reason = self._INSECURE[header]
                    if pattern.search(value.strip()):
                        insecure[header] = reason
            else:
                missing.append(header)

        return HeaderAudit(
            present=present,
            missing=missing,
            insecure_values=insecure,
        )


class ScriptAnalyser:
    """
    Passive analysis of inline <script> blocks.

    Only analyses scripts already present in the server response.
    Does not inject payloads or execute JavaScript.
    """

    def analyse(self, soup: BeautifulSoup) -> ScriptInfo:
        """
        Return ScriptInfo from all inline <script> blocks.

        External scripts (src attribute present) are counted but not
        analysed — their content is not available without a separate fetch.

        Args:
            soup: Parsed document.
        """
        hits: list[str] = []
        inline_count = 0

        for script in soup.find_all("script"):
            if not isinstance(script, Tag):
                continue
            if script.get("src"):
                continue  # external — skip content analysis

            inline_count += 1
            text = script.get_text()
            for pattern in _JS_SUSPICIOUS:
                if pattern.search(text):
                    # Use pattern.pattern as description (first 60 chars)
                    label = pattern.pattern[:60]
                    if label not in hits:
                        hits.append(label)

        return ScriptInfo(
            total_inline_scripts=inline_count,
            suspicious_pattern_hits=hits,
        )


class KeywordAnalyser:
    """Extract suspicious terms from visible body text with context snippets."""

    # Strip tags to get visible text, then scan for keywords
    _WHITESPACE = re.compile(r"\s+")

    def analyse(self, soup: BeautifulSoup) -> KeywordInfo:
        """
        Return KeywordInfo with matched keywords and context snippets.

        Uses BeautifulSoup's get_text() to extract visible text, then
        scans for each keyword in _SUSPICIOUS_KEYWORDS.

        Args:
            soup: Parsed document.
        """
        text = soup.get_text(separator=" ")
        text = self._WHITESPACE.sub(" ", text).strip()
        lower = text.lower()

        found: list[str] = []
        snippet_map: dict[str, str] = {}

        for kw in _SUSPICIOUS_KEYWORDS:
            idx = lower.find(kw)
            if idx != -1:
                found.append(kw)
                start = max(0, idx - 20)
                end   = min(len(text), idx + len(kw) + 60)
                snippet_map[kw] = text[start:end].strip()

        return KeywordInfo(found=found, snippet_map=snippet_map)


# ─── Analyser ─────────────────────────────────────────────────────────────────

class Analyser:
    """
    Orchestrates all five sub-analysers for a single ScanResult.

    Produces an AnalysisResult containing structured metadata without
    any scoring or classification decisions.

    Args:
        config: Full settings dict (from utils.load_config).
    """

    def __init__(self, config: dict) -> None:
        self._title   = TitleAnalyser()
        self._forms   = FormAnalyser()
        self._headers = HeaderAnalyser()
        self._scripts = ScriptAnalyser()
        self._keywords= KeywordAnalyser()

        global _log
        _log = get_logger(__name__, config)
        _log.debug("Analyser initialised")

    def analyse(self, scan_result: ScanResult) -> AnalysisResult:
        """
        Run all sub-analysers against one ScanResult.

        Returns an empty AnalysisResult for failed requests (no body to parse).

        Args:
            scan_result: Populated ScanResult from Scanner.get().

        Returns:
            AnalysisResult with all sub-analyser outputs populated.
        """
        if not scan_result.success:
            _log.debug("Skipping analysis for failed request: %s", scan_result.url)
            return self._empty(scan_result)

        try:
            soup = BeautifulSoup(scan_result.body, "lxml")
        except Exception:
            soup = BeautifulSoup(scan_result.body, "html.parser")

        title   = self._title.analyse(soup)
        forms   = self._forms.analyse(soup, scan_result.url)
        headers = self._headers.analyse(scan_result.headers)
        scripts = self._scripts.analyse(soup)
        keywords= self._keywords.analyse(soup)

        # Approximate word count from visible text
        visible = soup.get_text(separator=" ")
        word_count = len(visible.split())

        # Meta charset — check <meta charset> then Content-Type header
        charset = self._extract_charset(soup, scan_result.headers)

        result = AnalysisResult(
            url        = scan_result.url,
            status_code= scan_result.status_code,
            title      = title,
            forms      = forms,
            headers    = headers,
            scripts    = scripts,
            keywords   = keywords,
            meta_charset = charset,
            word_count = word_count,
        )

        _log.debug(
            "%s → forms=%d missing_headers=%d script_hits=%d kw=%d",
            scan_result.url, len(forms), len(headers.missing),
            len(scripts.suspicious_pattern_hits), len(keywords.found),
        )
        return result

    def analyse_many(self, scan_results: list[ScanResult]) -> list[AnalysisResult]:
        """
        Analyse a list of ScanResults (synchronous batch).

        Args:
            scan_results: List from Scanner.scan_urls() or Crawler.run().

        Returns:
            List of AnalysisResult in the same order as input.
        """
        results = [self.analyse(r) for r in scan_results]
        _log.info("Batch analysis complete: %d responses processed.", len(results))
        return results

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_charset(soup: BeautifulSoup, headers: dict[str, str]) -> str:
        """Return charset from <meta charset> or Content-Type header, else ''."""
        # 1. <meta charset="...">
        meta = soup.find("meta", attrs={"charset": True})
        if isinstance(meta, Tag):
            return str(meta.get("charset", "")).strip()
        # 2. <meta http-equiv="content-type" content="text/html; charset=...">
        meta2 = soup.find("meta", attrs={"http-equiv": re.compile("content-type", re.I)})
        if isinstance(meta2, Tag):
            content = str(meta2.get("content", ""))
            m = re.search(r"charset=([^\s;]+)", content, re.I)
            if m:
                return m.group(1).strip()
        # 3. Content-Type response header
        ct = headers.get("content-type", "")
        m = re.search(r"charset=([^\s;]+)", ct, re.I)
        return m.group(1).strip() if m else ""

    @staticmethod
    def _empty(scan_result: ScanResult) -> AnalysisResult:
        """Return a zero-content AnalysisResult for a failed request."""
        return AnalysisResult(
            url        = scan_result.url,
            status_code= scan_result.status_code,
            title      = TitleInfo(raw="", lower=""),
            forms      = [],
            headers    = HeaderAudit(),
            scripts    = ScriptInfo(),
            keywords   = KeywordInfo(),
        )
