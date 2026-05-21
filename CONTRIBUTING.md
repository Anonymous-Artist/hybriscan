# Contributing to HybriScan

HybriScan is a research prototype. Contributions that improve detection
accuracy, reduce false positives, or strengthen the research foundation
are welcome.

## Ground rules

- This project must remain research-safe. Do not add exploit automation,
  payload chaining, or bypass techniques.
- All new patterns must include a description, weight justification, and
  at least one corresponding test case in `test_detector.py`.
- All PRs must pass the full test suite (`pytest tests/ -q`).

## Development setup

```bash
git clone https://github.com/yourusername/hybriscan.git
cd hybriscan
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest tests/ -q   # must be 340 passed
```

## What to contribute

| Area | Examples |
|---|---|
| Pattern banks | New CMS admin paths, additional DB error signatures |
| Detection categories | API misconfiguration, CORS header issues |
| Wordlist expansion | `config/wordlists/admin_paths.txt` |
| Test cases | Hard-negative tests, edge-case URLs |
| Documentation | Architecture diagrams, demo recordings |
| Bug fixes | False positives, scoring edge cases |

## What not to contribute

- Active exploit payloads or bypass techniques
- Patterns sourced from non-public CVE PoCs without attribution
- Features that require unauthenticated destructive behaviour

## Commit style

```
feat(detector): add Spring Boot actuator pattern bank
fix(scorer): clamp bonus to max 1.0 when stacked
test(crawler): add depth-limit edge case
docs(readme): update threshold guidance table
```

## Reporting issues

Include: Python version, target type (DVWA/WebGoat/other),
`settings.yaml` diff, and the full `hybriscan.log` output.
