# HybriScan — Architecture Reference

## Module responsibilities

| Module | Responsibility | Key output type |
|---|---|---|
| `utils.py` | Logging, config loading, URL normalisation | `dict`, `Logger` |
| `scanner.py` | Async HTTP requests, session, retry | `ScanResult` |
| `crawler.py` | BFS link discovery, deduplication | `list[CrawlPage]` |
| `detector.py` | Regex pattern matching, raw score computation | `DetectionResult` |
| `analyzer.py` | HTML/form/header/JS structural analysis | `AnalysisResult` |
| `scorer.py` | Score aggregation, threshold, severity label | `ScoringResult` |
| `reporter.py` | JSON schema construction, file I/O | `dict`, `Path` |
| `payload_tester.py` | Opt-in reflection + error indicator probes | `UrlTestSummary` |
| `pipeline.py` | End-to-end orchestration | `PipelineResult` |
| `main.py` | CLI argument parsing, config override, `asyncio.run` | exit code |

## Execution flow

```
main.py
  └─ Pipeline.run(url)
       │
       ├─ 1. _collect_urls()
       │      ├─ base URL
       │      ├─ wordlist expansion (admin_paths.txt, common_paths.txt)
       │      └─ Crawler.run() → discovered internal links  [if --crawl]
       │
       ├─ 2. Scanner.scan_urls(urls)
       │      └─ async GET × N URLs (semaphore-bounded)
       │         → list[ScanResult]
       │
       ├─ 3. Detector.analyse_many(scan_results)
       │      └─ per URL: search_target = url + " " + body
       │         → score each PatternBank → normalise → DetectionResult
       │
       ├─ 4. Analyser.analyse_many(scan_results)
       │      ├─ TitleAnalyser   → TitleInfo
       │      ├─ FormAnalyser    → list[FormInfo]
       │      ├─ HeaderAnalyser  → HeaderAudit
       │      ├─ ScriptAnalyser  → ScriptInfo
       │      └─ KeywordAnalyser → KeywordInfo
       │         → AnalysisResult
       │
       ├─ 5. PayloadTester.test_url()  [if --payloads]
       │      ├─ baseline GET
       │      ├─ for each param × payload: GET → compare_responses()
       │      └─ → UrlTestSummary (anomaly list)
       │
       ├─ 6. Scorer.score_many(zip(det_results, ana_results))
       │      ├─ _compute_bonuses()  ← analyser signals
       │      ├─ _adjust_scores()   ← weight × detection + bonus
       │      ├─ _aggregate()       ← max-pool
       │      ├─ _severity()        ← band lookup
       │      └─ _confidence()      ← tanh sigmoid
       │         → ScoringResult
       │
       └─ 7. Reporter.build() + Reporter.save()
              → JSON report file
```

## Scoring detail

### Pattern bank scoring (Algorithm 1)

Each PatternBank contains `(regex, weight, description)` triples.
For a given URL + body string:

```python
raw_score = sum(weight for p in bank if p.regex.search(target))
norm_score = min(1.0, raw_score / sum(p.weight for p in bank))
```

Binary match contribution (`min(match_count, 1)`) prevents a single
repeated pattern from dominating the score.

### Composite aggregation

```python
composite = max(adj_score(C) for C in categories)   # max-pool (default)
# or
composite = mean(adj_score(C) for C in categories)  # weighted_avg (future)
```

### Adaptive threshold (Algorithm 2)

```python
if observed_fpr > target_fpr:
    T = min(max_threshold, T + 0.01)   # tighten: reduce FPs
elif observed_accuracy < target_accuracy:
    T = max(min_threshold, T - 0.01)   # loosen: recover TPs
```

Requires ground-truth labels; operates in Phase 9 integration layer.

## Payload testing flow

```
PayloadTester.test_url(scanner, url, baseline)
  │
  ├─ extract_query_params(url)        → ["id", "q", ...]
  ├─ baseline = scanner.get(url)      → ScanResult
  └─ for param in params:
       for payload in sqli_payloads + xss_payloads:
         probed_url = inject_payload(url, param, payload.value)
         probed     = scanner.get(probed_url)
         cmp        = compare_responses(baseline, probed, payload)
         if _is_anomaly(cmp): anomalies.append(PayloadResult)
```

Anomaly signals: status code change · content-length delta > 5% ·
SQL error signature · verbatim payload reflection.

## Data flow diagram

```
ScanResult ──────────────────────────────────────────────┐
    │                                                      │
    ▼                                                      ▼
DetectionResult                                     AnalysisResult
    │                                                      │
    └──────────────────┬───────────────────────────────────┘
                       ▼
                 ScoringResult
                       │
                       ▼
                  PipelineResult
                       │
                       ▼
                  JSON Report
```
