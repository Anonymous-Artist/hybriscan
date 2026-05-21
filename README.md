# HybriScan

**A Category-Aware, Weighted Heuristic Web Vulnerability Scanner  
with Adaptive Threshold Optimisation**

> Passive response-content analysis to reduce false positives in  
> web vulnerability detection — without active exploitation.

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-340%20passing-brightgreen)]()
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Research%20Prototype-orange)]()

---

## Overview

HybriScan augments conventional wordlist-based path enumeration with a
**weighted, multi-category response-content scoring engine**.

Traditional scanners (Nikto, Gobuster, Dirsearch) classify endpoints by
URL path matching alone — producing false-positive rates of 50–100% in
real deployments. HybriScan addresses this by computing a
**four-dimensional vulnerability score vector** from both the URL
structure and the HTTP response body, then applying an **adaptive
threshold** to govern classification.

> **Research context:** This tool accompanies the paper  
> *HybriScan: A Category-Aware, Weighted Heuristic Web Vulnerability  
> Scanner with Adaptive Threshold Optimisation*  
> (Suthar, Gupta, Solanki — Sankalchand Patel University, 2024)

---

## Key Results

Evaluated against a controlled 27-endpoint dataset:

| Metric | Wordlist baseline | HybriScan |
|---|---|---|
| Accuracy | 44.44% | **77.78%** |
| Precision | 46.15% | **88.89%** |
| F1 Score | 0.615 | **0.727** |
| False Positive Rate | 100.00% | **7.14%** |

HybriScan eliminated **13 of 14 false positives** (93% reduction)
relative to pure wordlist matching.

---

## Features

| Feature | Details |
|---|---|
| Async HTTP engine | `aiohttp` session with configurable concurrency, retry, timeout |
| BFS crawler | Internal-link discovery, depth control, robots.txt support |
| Pattern detection | 6 categories, 70+ compiled regex patterns with weighted scoring |
| Response analysis | Form extraction, security header audit, inline JS analysis |
| Adaptive threshold | Configurable T ∈ [0.50, 0.82], auto-adjustable on observed FPR |
| Payload testing | Opt-in reflection + SQL error indicator probes (research-safe) |
| JSON reporting | Timestamped reports with per-endpoint evidence and risk summary |
| 340 unit tests | pytest suite covering all modules end-to-end |

---

## Detection Categories

| Category | OWASP 2021 | Signal sources |
|---|---|---|
| Admin interface exposure | A01 Broken Access Control | URL path + title + body keywords |
| SQL injection indicators | A03 Injection | DB error message leakage |
| Authentication endpoint | A07 Auth Failures | Password form + URL structure |
| Directory listing | A05 Security Misconfiguration | HTML index markers |
| XSS surface indicators | A03 Injection | URL reflection + DOM sinks |
| Sensitive file exposure | A05 Security Misconfiguration | Known path + body content markers |

---

## Architecture

```
CLI (main.py)
    │
    └─► Pipeline (core/pipeline.py)
            │
            ├─► Scanner      async HTTP engine, session, retry
            ├─► Crawler      BFS link discovery, deduplication
            ├─► Detector     regex pattern banks, weighted scoring
            ├─► Analyser     HTML/form/header/script analysis
            ├─► PayloadTester opt-in reflection + error probes
            ├─► Scorer       score aggregation, threshold, severity
            └─► Reporter     JSON report, risk summary
```

### Scoring Model

```
For each category C ∈ {admin, sqli, login, dir_listing, xss, sensitive}:

  raw_score(C)  = Σ weight(p) · ⌊match(p, url+body) > 0⌋   ∀p ∈ bank(C)
  norm_score(C) = min(1.0, raw_score(C) / max_score(C))
  adj_score(C)  = min(1.0, norm_score(C) · weight(C) + bonus(C))

composite      = max(adj_score(C))          # max-pool aggregation
label          = VULNERABLE  if composite ≥ T  else  BENIGN
confidence     = 0.5 + 0.5 · tanh(6 · (composite − T))
```

Threshold T is initialised from `settings.yaml` and can be
updated adaptively using observed FPR and accuracy (Algorithm 2).

---

## Project Structure

```
hybriscan/
├── core/
│   ├── scanner.py        Async HTTP engine, ScanResult dataclass
│   ├── crawler.py        BFS crawler, CrawlPage, URL normalisation
│   ├── detector.py       6 PatternBanks, DetectionResult, Detector
│   ├── analyzer.py       5 sub-analysers, AnalysisResult, Analyser
│   ├── scorer.py         Scorer, ScoringResult, Severity, Label
│   ├── reporter.py       Reporter, JSON schema builders
│   ├── payload_tester.py PayloadTester, compare_responses
│   ├── pipeline.py       Pipeline orchestrator, print_summary
│   └── utils.py          Logging, config loader, URL helpers
├── payloads/
│   ├── sqli.txt          11 error-induction probes
│   └── xss.txt           7 reflection-detection probes
├── config/
│   ├── settings.yaml     Master configuration
│   └── wordlists/        admin_paths.txt, common_paths.txt
├── reports/              Generated JSON reports (gitignored)
├── tests/                340 pytest tests (8 modules)
├── docs/                 Architecture diagrams, paper appendix
├── main.py               CLI entry point (argparse)
├── requirements.txt
├── LICENSE
└── README.md
```

---

## Installation

```bash
git clone https://github.com/yourusername/hybriscan.git
cd hybriscan
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

**Python 3.12+ required.**

---

## Usage

> ⚠️ **Authorisation required.** Only scan systems you own or have
> explicit written permission to test. See [Ethical Notice](#ethical-notice).

### Basic scan

```bash
python main.py --url http://target.local
```

### With crawler enabled

```bash
python main.py --url http://target.local --crawl --depth 2
```

### Custom threshold (lower → higher recall, more FPs)

```bash
python main.py --url http://target.local --threshold 0.65
```

### Enable payload testing + verbose output

```bash
python main.py --url http://target.local --payloads --verbose
```

### Full example with all options

```bash
python main.py \
  --url http://dvwa.local \
  --crawl --depth 2 \
  --threshold 0.70 \
  --concurrency 5 \
  --payloads \
  --output reports/dvwa_scan.json \
  --verbose
```

### CLI reference

| Flag | Default | Description |
|---|---|---|
| `--url` | required | Target base URL |
| `--crawl` | off | Enable BFS link crawler |
| `--depth` | 2 | Crawl depth |
| `--threshold` | 0.70 | Classification threshold (0.50–0.82) |
| `--concurrency` | 10 | Async request concurrency |
| `--payloads` | off | Enable lightweight payload testing |
| `--output` | auto | JSON report path |
| `--verbose` | off | Print per-endpoint score vectors |
| `--config` | config/settings.yaml | Config file path |

---

## Sample Output

```
────────────────────────────────────────────────────────────
  HybriScan — Scan Summary
────────────────────────────────────────────────────────────
  Target    : http://dvwa.local
  Started   : 2024-11-01T09:15:32Z
  Finished  : 2024-11-01T09:15:44Z
  Endpoints : 27
  Vulnerable: 8
  Benign    : 19
  Max score : 0.8932

  Severity breakdown:
    critical  : 2
    high      : 3
    medium    : 3

  Top findings (5):
    [critical] 0.8932  http://dvwa.local/phpmyadmin/
    [critical] 0.8750  http://dvwa.local/wp-admin/
    [high    ] 0.7214  http://dvwa.local/login.php
    [high    ] 0.6983  http://dvwa.local/.env
    [medium  ] 0.5120  http://dvwa.local/admin/

  Report    : reports/hybriscan_dvwa.local_2024-11-01T09-15-44.json
────────────────────────────────────────────────────────────
```

### Sample JSON report (excerpt)

```json
{
  "meta": {
    "hybriscan_version": "1.0.0",
    "target_url": "http://dvwa.local",
    "endpoints_scanned": 27,
    "threshold_used": 0.7
  },
  "summary": {
    "total_endpoints": 27,
    "vulnerable_count": 8,
    "severity_breakdown": {
      "critical": 2, "high": 3, "medium": 3, "low": 0, "none": 19
    }
  },
  "endpoints": [
    {
      "url": "http://dvwa.local/phpmyadmin/",
      "label": "vulnerable",
      "severity": "critical",
      "composite_score": 0.8932,
      "dominant_category": "admin",
      "evidence": [
        {"category": "admin", "description": "phpMyAdmin path", "weight": 0.95}
      ],
      "missing_headers": ["content-security-policy", "x-frame-options"]
    }
  ]
}
```

---

## Running Tests

```bash
# Full suite
pytest tests/ -v

# Single module
pytest tests/test_detector.py -v

# With coverage
pytest tests/ --cov=core --cov-report=term-missing
```

---

## Configuration

All behaviour is controlled via `config/settings.yaml`:

```yaml
scanner:
  concurrency: 10       # async request limit
  timeout: 10           # seconds per request
  max_retries: 2

scoring:
  initial_threshold: 0.70   # starting classification threshold
  min_threshold: 0.50       # adaptive lower bound
  max_threshold: 0.82       # adaptive upper bound

payloads:
  enabled: false            # opt-in payload testing
```

See [config/settings.yaml](config/settings.yaml) for all options.

---

## Research Alignment

This implementation maps to the paper as follows:

| Paper component | Implementation |
|---|---|
| Algorithm 1 — ComputeVulnerabilityScore | `Detector._score_bank()` + `Scorer._aggregate()` |
| Algorithm 2 — AdaptiveThresholdOptimise | `Scorer.update_threshold()` |
| Table II — Category pattern weights | `core/detector.py` PatternBanks |
| Section V — Five-layer pipeline | `core/pipeline.py` Pipeline |
| Section VIII — Hard-negative discrimination | `test_detector.py` hard-neg tests |

### Realistic limitations

- Pattern weights were tuned on a 27-endpoint controlled dataset — production generalisation requires re-evaluation on broader targets.
- Adaptive threshold update requires ground-truth labels; without them, the initial threshold is static.
- Payload testing is indicator-based, not exploitation-based — it detects *surfaces*, not confirmed vulnerabilities.
- The crawler does not render JavaScript — SPA content is not scanned.

---

## Ethical Notice

HybriScan is built for **authorised security assessment and academic
research only**. Deploying this tool against systems without explicit
written permission may violate applicable law, including:

- Computer Fraud and Abuse Act (USA)
- Computer Misuse Act 1990 (UK)
- Information Technology Act 2000 (India)

**Recommended test environments:**

| Environment | URL |
|---|---|
| DVWA | https://github.com/digininja/DVWA |
| OWASP WebGoat | https://owasp.org/www-project-webgoat/ |
| Mutillidae II | https://github.com/webpwnized/mutillidae |

The authors accept no liability for misuse.

---

## Future Work

- [ ] ML-based weight optimisation (scikit-learn placeholder ready)
- [ ] HTML report rendering (Phase 10 hook in `reporter.py`)
- [ ] JavaScript rendering via Playwright for SPA scanning
- [ ] Per-category adaptive threshold (replace single global T)
- [ ] Authenticated scan support (session cookie injection)
- [ ] CVSS score mapping for findings

---

## Citation

This project is archived on Zenodo and can be cited using the following DOI:

DOI: https://doi.org/10.5281/zenodo.20320638

```bibtex
@article{suthar2024hybriscan,
  title     = {HybriScan: A Category-Aware, Weighted Heuristic Web
               Vulnerability Scanner with Adaptive Threshold Optimisation},
  author    = {Suthar, Dishant P.and Solanki, Udbodh V.},
  year      = {2024},
  note      = {Gujarat, India}
}
```

---

## License

MIT — see [LICENSE](LICENSE).
