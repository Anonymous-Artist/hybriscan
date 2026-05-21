"""
HybriScan — CLI entry point
────────────────────────────
Category-Aware Heuristic Web Vulnerability Scanner with Adaptive
Threshold Optimisation.  Research prototype — scan only systems you
are explicitly authorised to test.

Usage examples
--------------
  python main.py --url http://target.local
  python main.py --url http://target.local --crawl --depth 2 --verbose
  python main.py --url http://target.local --threshold 0.75 --output reports/out.json
  python main.py --url http://target.local --payloads --concurrency 5
"""

import argparse
import asyncio
import sys
from pathlib import Path

import yaml

from core.pipeline import Pipeline, print_summary
from core.utils import get_logger

_log = get_logger(__name__)


# ─── Config ───────────────────────────────────────────────────────────────────

def load_config(path: str) -> dict:
    """Load and return settings.yaml; exit on missing file."""
    p = Path(path)
    if not p.exists():
        print(f"[ERROR] Config file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    """Define and parse CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="hybriscan",
        description=(
            "HybriScan — Category-Aware Heuristic Web Vulnerability Scanner\n"
            "Research prototype. Scan only systems you are authorised to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--url", required=True,
        help="Target base URL (e.g. http://target.local)",
    )
    parser.add_argument(
        "--crawl", action="store_true",
        help="Enable BFS link crawler from the target URL",
    )
    parser.add_argument(
        "--depth", type=int, default=None,
        help="Crawl depth (overrides settings.yaml; default: 2)",
    )
    parser.add_argument(
        "--threshold", type=float, default=None,
        help="Classification threshold override (0.50–0.82)",
    )
    parser.add_argument(
        "--concurrency", type=int, default=None,
        help="Async HTTP concurrency limit (overrides settings.yaml)",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="JSON report output path (overrides settings.yaml output_dir)",
    )
    parser.add_argument(
        "--payloads", action="store_true",
        help="Enable lightweight payload testing (disabled by default)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print per-endpoint score vectors in summary",
    )
    parser.add_argument(
        "--config", type=str, default="config/settings.yaml",
        help="Path to settings.yaml (default: config/settings.yaml)",
    )
    return parser.parse_args()


def apply_cli_overrides(config: dict, args: argparse.Namespace) -> dict:
    """
    Apply CLI flag overrides to the config dict.

    CLI arguments take precedence over settings.yaml values.
    Returns the modified config (mutated in-place for simplicity).
    """
    if args.threshold is not None:
        config.setdefault("scoring", {})["initial_threshold"] = args.threshold

    if args.concurrency is not None:
        config.setdefault("scanner", {})["concurrency"] = args.concurrency

    if args.depth is not None:
        config.setdefault("crawler", {})["max_depth"] = args.depth

    if args.output is not None:
        output_path = Path(args.output)
        config.setdefault("reporting", {})["output_dir"] = str(output_path.parent)

    if args.payloads:
        config.setdefault("payloads", {})["enabled"] = True

    if args.verbose:
        config.setdefault("reporting", {})["verbose"] = True

    return config


# ─── Entry point ──────────────────────────────────────────────────────────────

async def _run(args: argparse.Namespace, config: dict) -> int:
    """
    Async scan entry point.

    Returns:
        Exit code: 0 on success, 1 on pipeline error.
    """
    pipeline = Pipeline(
        config  = config,
        crawl   = args.crawl,
        verbose = args.verbose,
    )

    result = await pipeline.run(args.url)
    print_summary(result, verbose=args.verbose)

    return 1 if result.error else 0


def main() -> None:
    """CLI entry point — parse args, load config, run async pipeline."""
    args   = parse_args()
    config = load_config(args.config)
    config = apply_cli_overrides(config, args)

    _log = get_logger(__name__, config)
    exit_code = asyncio.run(_run(args, config))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
