"""
core/utils.py
─────────────
Shared utilities: structured logging setup and YAML config loader.
Used by all pipeline modules — initialise logger once via get_logger().
"""

import logging
import sys
from pathlib import Path
from typing import Any

import yaml


# ─── Logging ──────────────────────────────────────────────────────────────────

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def get_logger(name: str, config: dict | None = None) -> logging.Logger:
    """
    Return a named logger configured from settings.yaml.

    On first call for a given name, attaches a StreamHandler (and optionally a
    FileHandler if logging.log_to_file is True in config).  Subsequent calls
    return the cached logger unchanged — safe to call at module level.

    Args:
        name:   Logger name, typically __name__ of the calling module.
        config: Full settings dict (from load_config).  Pass None to use
                INFO level with stdout only.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # already configured

    level_str: str = "INFO"
    log_to_file: bool = False
    log_file: str = "reports/hybriscan.log"

    if config:
        log_cfg = config.get("logging", {})
        level_str = log_cfg.get("level", "INFO").upper()
        log_to_file = log_cfg.get("log_to_file", False)
        log_file = log_cfg.get("log_file", log_file)

    level = getattr(logging, level_str, logging.INFO)
    logger.setLevel(level)

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    if log_to_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.propagate = False
    return logger


# ─── Config ───────────────────────────────────────────────────────────────────

def load_config(config_path: str = "config/settings.yaml") -> dict[str, Any]:
    """
    Load and return the YAML configuration file.

    Args:
        config_path: Path to settings.yaml (relative or absolute).

    Returns:
        Parsed config as a nested dict.

    Raises:
        FileNotFoundError: If the config file does not exist.
        yaml.YAMLError:    If the file is malformed.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ─── URL helpers ──────────────────────────────────────────────────────────────

def normalise_url(url: str) -> str:
    """
    Strip trailing slash and lower-case the scheme+host portion.

    Args:
        url: Raw URL string.

    Returns:
        Normalised URL string.
    """
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    scheme, rest = url.split("://", 1)
    if "/" in rest:
        host, path = rest.split("/", 1)
        url = f"{scheme.lower()}://{host.lower()}/{path}"
    else:
        url = f"{scheme.lower()}://{rest.lower()}"
    return url.rstrip("/")
