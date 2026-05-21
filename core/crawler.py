"""
core/crawler.py
───────────────
Async internal-link crawler for HybriScan.

Responsibilities
----------------
- Accept a base URL and crawl all reachable internal pages up to a
  configurable depth and page cap.
- Extract anchor href links from each page using BeautifulSoup4.
- Normalise, filter, and deduplicate discovered URLs before queuing.
- Strictly restrict crawling to the origin domain — never follow
  external links.
- Optionally honour robots.txt disallow rules.
- Return a flat list of CrawlPage objects for downstream detection.

Integration
-----------
Crawler.run() requires an already-open Scanner instance so both the
crawler and the wordlist scanner share one aiohttp session and one
concurrency semaphore.

Example::

    async with Scanner(config) as scanner:
        crawler = Crawler(config, base_url="http://target.local")
        pages   = await crawler.run(scanner)
        urls    = Crawler.discovered_urls(pages)
"""

import asyncio
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup

from core.scanner import ScanResult, Scanner
from core.utils import get_logger, normalise_url

_log = get_logger(__name__)

_DEFAULT_FILTER_EXTENSIONS = [
    ".png", ".jpg", ".gif", ".css", ".js",
    ".ico", ".svg", ".woff", ".pdf", ".zip",
]


# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class CrawlPage:
    """
    A single crawled page — URL, HTTP result, and crawl metadata.
    Passed to the detection pipeline as the primary unit of analysis.
    """
    url: str
    depth: int
    result: ScanResult


@dataclass
class CrawlerConfig:
    """Typed view of the crawler section of settings.yaml."""
    max_depth: int                  = 2
    max_pages: int                  = 100
    respect_robots_txt: bool        = True
    url_filter_extensions: list[str] = field(
        default_factory=lambda: list(_DEFAULT_FILTER_EXTENSIONS)
    )


# ─── Config ───────────────────────────────────────────────────────────────────

def _parse_config(config: dict) -> CrawlerConfig:
    """Extract and type-coerce the crawler block from the settings dict."""
    raw = config.get("crawler", {})
    extensions = raw.get("url_filter_extensions")
    if not extensions:
        extensions = list(_DEFAULT_FILTER_EXTENSIONS)
    return CrawlerConfig(
        max_depth            = int(raw.get("max_depth", 2)),
        max_pages            = int(raw.get("max_pages", 100)),
        respect_robots_txt   = bool(raw.get("respect_robots_txt", True)),
        url_filter_extensions= list(extensions),
    )


# ─── URL Helpers ──────────────────────────────────────────────────────────────

def _origin(url: str) -> str:
    """
    Return the scheme + netloc (origin) of a URL.

    Example::
        _origin("http://target.local/admin/panel") → "http://target.local"
    """
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _normalise_internal(href: str, base_url: str) -> str | None:
    """
    Resolve a raw href against base_url and return a normalised absolute URL.

    Returns None for:
    - Non-HTTP schemes (javascript:, mailto:, data:, tel:)
    - Fragment-only links (#section)
    - Empty strings
    - URLs that resolve outside the base origin

    Args:
        href:     Raw href attribute value (relative or absolute).
        base_url: Absolute URL of the page being parsed.

    Returns:
        Normalised absolute URL string, or None if the link should be skipped.
    """
    href = href.strip()
    if not href:
        return None

    # Reject non-HTTP schemes before any resolution
    lower = href.lower()
    for scheme in ("javascript:", "mailto:", "data:", "tel:"):
        if lower.startswith(scheme):
            return None

    # Fragment-only links are not separate resources
    if href.startswith("#"):
        return None

    # Resolve relative URLs against the page URL
    absolute = urljoin(base_url, href)

    # Reject anything that didn't resolve to http/https
    parsed = urlparse(absolute)
    if parsed.scheme not in ("http", "https"):
        return None

    # Strip fragment (#section) — same page, different anchor
    clean = urlunparse(parsed._replace(fragment=""))

    # Normalise trailing slash / scheme case
    clean = normalise_url(clean)

    # Reject external origins
    if _origin(clean) != _origin(normalise_url(base_url)):
        return None

    return clean


def _has_filtered_extension(url: str, extensions: list[str]) -> bool:
    """
    Return True if the URL path ends with a filtered extension.

    Comparison is case-insensitive; query strings are ignored.

    Args:
        url:        Absolute URL to inspect.
        extensions: Dot-prefixed extensions, e.g. [".png", ".css"].
    """
    path = urlparse(url).path.lower()
    return any(path.endswith(ext.lower()) for ext in extensions)


# ─── Robots.txt ───────────────────────────────────────────────────────────────

class _RobotsGuard:
    """
    Lightweight robots.txt checker.

    Fetches and parses robots.txt once per crawl run.
    If the file is unavailable, all URLs are permitted.
    """

    def __init__(self, user_agent: str) -> None:
        self._ua = user_agent
        self._parser: RobotFileParser | None = None
        self._enabled: bool = False

    async def load(self, base_url: str, scanner: Scanner) -> None:
        """
        Fetch and parse robots.txt from the target origin.

        Args:
            base_url: Target origin URL.
            scanner:  Open Scanner instance for the HTTP fetch.
        """
        robots_url = f"{_origin(base_url)}/robots.txt"
        result = await scanner.get(robots_url)
        if result.success and result.status_code == 200 and result.body:
            self._parser = RobotFileParser()
            self._parser.parse(result.body.splitlines())
            self._enabled = True
            _log.debug("robots.txt loaded from %s", robots_url)
        else:
            _log.debug("robots.txt not available at %s — all paths permitted", robots_url)

    def is_allowed(self, url: str) -> bool:
        """Return True if the URL may be fetched per robots.txt rules."""
        if not self._enabled or self._parser is None:
            return True
        return self._parser.can_fetch(self._ua, url)


# ─── Crawler ──────────────────────────────────────────────────────────────────

class Crawler:
    """
    BFS async crawler restricted to the target origin.

    Uses a deque as the BFS frontier and a set for O(1) duplicate
    detection.  Terminates when the frontier empties, max_pages is
    reached, or all pages within max_depth are visited.

    The crawler does NOT manage its own aiohttp session — it borrows
    the caller's open Scanner to share the connection pool and
    concurrency semaphore.

    Args:
        config:   Full settings dict (from utils.load_config).
        base_url: Target base URL to start crawling from.
    """

    def __init__(self, config: dict, base_url: str) -> None:
        self._cfg    = _parse_config(config)
        self._base   = normalise_url(base_url)
        self._origin = _origin(self._base)
        self._ua: str = config.get("scanner", {}).get("user_agent", "HybriScan/1.0")

        global _log
        _log = get_logger(__name__, config)
        _log.debug(
            "Crawler initialised: origin=%s max_depth=%d max_pages=%d",
            self._origin, self._cfg.max_depth, self._cfg.max_pages,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    async def run(self, scanner: Scanner) -> list[CrawlPage]:
        """
        Execute the BFS crawl and return all fetched pages.

        Args:
            scanner: An already-open Scanner instance.

        Returns:
            List of CrawlPage in BFS discovery order.
        """
        robots = _RobotsGuard(self._ua)
        if self._cfg.respect_robots_txt:
            await robots.load(self._base, scanner)

        visited:  set[str]               = set()
        pages:    list[CrawlPage]        = []
        frontier: deque[tuple[str, int]] = deque()   # (url, depth)

        frontier.append((self._base, 0))
        visited.add(self._base)

        _log.info("Crawl started: %s", self._base)

        while frontier:
            if len(pages) >= self._cfg.max_pages:
                _log.info("Page cap (%d) reached — stopping crawl.", self._cfg.max_pages)
                break

            batch = self._drain(frontier)
            results = await asyncio.gather(*[scanner.get(url) for url, _ in batch])

            for (url, depth), result in zip(batch, results):
                page = CrawlPage(url=url, depth=depth, result=result)
                pages.append(page)

                if not result.success:
                    _log.debug("Link extraction skipped for failed URL: %s", url)
                    continue

                _log.info("[depth=%d] %s → HTTP %s (%.1fms)",
                          depth, url, result.status_code, result.elapsed_ms)

                if depth < self._cfg.max_depth:
                    child_urls = self._extract_links(result.body, url)
                    for child in self._filter_new(child_urls, visited, robots):
                        frontier.append((child, depth + 1))
                        visited.add(child)

        _log.info("Crawl complete: %d pages collected.", len(pages))
        return pages

    # ── Internal ──────────────────────────────────────────────────────────────

    def _drain(self, frontier: deque[tuple[str, int]]) -> list[tuple[str, int]]:
        """
        Pull up to 10 entries from the BFS frontier for concurrent fetching.

        Batch size matches the default scanner concurrency to avoid
        overwhelming the semaphore gate.
        """
        batch: list[tuple[str, int]] = []
        while frontier and len(batch) < 10:
            batch.append(frontier.popleft())
        return batch

    def _extract_links(self, html: str, page_url: str) -> list[str]:
        """
        Parse HTML and return normalised, unique, internal absolute URLs.

        Only <a href="..."> anchors are considered.  Invalid, external,
        or filtered-extension URLs are silently discarded.

        Args:
            html:     Raw HTML body string.
            page_url: Absolute URL of the page being parsed.

        Returns:
            Deduplicated list of internal URL strings.
        """
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")

        seen: set[str] = set()
        links: list[str] = []

        for tag in soup.find_all("a", href=True):
            url = _normalise_internal(tag["href"], page_url)
            if url is None:
                continue
            if _has_filtered_extension(url, self._cfg.url_filter_extensions):
                continue
            if url not in seen:
                seen.add(url)
                links.append(url)

        _log.debug("Extracted %d internal links from %s", len(links), page_url)
        return links

    def _filter_new(
        self,
        urls: list[str],
        visited: set[str],
        robots: _RobotsGuard,
    ) -> list[str]:
        """
        Return unvisited URLs that are permitted by robots.txt.

        Args:
            urls:    Candidate URLs from link extraction.
            visited: Global visited set for this crawl run.
            robots:  Robots guard for disallow-rule checking.
        """
        new: list[str] = []
        for url in urls:
            if url in visited:
                continue
            if not robots.is_allowed(url):
                _log.debug("robots.txt disallows: %s", url)
                continue
            new.append(url)
        return new

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    def discovered_urls(pages: list[CrawlPage]) -> list[str]:
        """
        Return a flat ordered list of URLs from a completed crawl.

        Convenience method for feeding crawler output directly into
        the detection pipeline.

        Args:
            pages: Output of Crawler.run().

        Returns:
            List of URL strings in discovery order.
        """
        return [p.url for p in pages]
