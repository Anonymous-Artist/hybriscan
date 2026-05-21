"""
core/scorer.py
──────────────
Weighted vulnerability scoring engine for HybriScan.

Implements Algorithm 2 (AdaptiveThresholdOptimise) from the paper and
the final classification step that converts raw category scores into a
structured ScoringResult with severity label and confidence estimate.

Pipeline position
-----------------
Scorer sits between the detection/analysis layer and the reporter:

    DetectionResult  ─┐
                       ├─► Scorer.score() ─► ScoringResult ─► reporter.py
    AnalysisResult   ─┘

Scoring model
-------------
The scorer merges two signal sources per URL:

  1. Detection signals  (detector.py) — per-category normalised scores
     [0, 1] from regex pattern matching on URL + response body.

  2. Analyser signals   (analyzer.py) — structural metadata signals that
     supplement or penalise the detection score:
       • Weak/missing security headers         → bonus for header category
       • Password form on suspicious action    → bonus for login category
       • Suspicious inline JS patterns         → bonus for XSS category
       • Sensitive keyword presence            → small bonus to dominant cat

Score aggregation
-----------------
  adjusted_score(cat) = min(1.0,
      detection_score(cat) * category_weight(cat) +
      analyser_bonus(cat)
  )
  composite = max(adjusted_score(cat) for cat in categories)

Severity levels
---------------
  Critical  composite ≥ 0.75
  High      composite ≥ 0.55
  Medium    composite ≥ 0.35
  Low       composite ≥ 0.10
  None      composite <  0.10   (not flagged)

Threshold classification
------------------------
  label = VULNERABLE if composite ≥ threshold else BENIGN
  The operating threshold comes from settings.yaml[scoring.initial_threshold]
  and can be overridden at runtime.  Adaptive update logic (Algorithm 2)
  is provided as Scorer.update_threshold() for Phase 9 integration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from core.analyzer import AnalysisResult
from core.detector import DetectionResult
from core.utils import get_logger

_log = get_logger(__name__)


# ─── Enums ────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    """Risk severity label assigned to a scored URL."""
    NONE     = "none"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class Label(str, Enum):
    """Binary classification label relative to the active threshold."""
    VULNERABLE = "vulnerable"
    BENIGN     = "benign"


# ─── Severity thresholds ─────────────────────────────────────────────────────
# These are scoring-layer constants, not the adaptive classification threshold.
# Intentionally modest — avoids overclaiming certainty on passive indicators.

_SEVERITY_BANDS: tuple[tuple[float, Severity], ...] = (
    (0.75, Severity.CRITICAL),
    (0.55, Severity.HIGH),
    (0.35, Severity.MEDIUM),
    (0.10, Severity.LOW),
    (0.00, Severity.NONE),
)

# Analyser bonus weights — additive, capped by min(1.0, ...) on final score.
# Kept small to avoid letting structural signals override evidence-free URLs.
_HEADER_MISSING_BONUS:   float = 0.04   # per missing security header (capped at 4)
_HEADER_INSECURE_BONUS:  float = 0.05   # per insecure header value
_PASSWORD_FORM_BONUS:    float = 0.08   # password form on suspicious action
_JS_PATTERN_BONUS:       float = 0.06   # per distinct suspicious JS pattern (cap 2)
_KEYWORD_BONUS:          float = 0.03   # per sensitive keyword found (cap 3)


# ─── Config ───────────────────────────────────────────────────────────────────

@dataclass
class ScoringConfig:
    """Typed view of settings.yaml[scoring]."""
    initial_threshold: float  = 0.70
    min_threshold:     float  = 0.50
    max_threshold:     float  = 0.82
    target_fpr:        float  = 0.15
    target_accuracy:   float  = 0.75
    max_iterations:    int    = 30
    aggregation:       str    = "max_pool"
    # Per-category weights (from detection.category_weights in settings)
    category_weights:  dict[str, float] = field(default_factory=dict)


def _parse_config(config: dict) -> ScoringConfig:
    sc = config.get("scoring", {})
    dw = config.get("detection", {}).get("category_weights", {})
    return ScoringConfig(
        initial_threshold = float(sc.get("initial_threshold", 0.70)),
        min_threshold     = float(sc.get("min_threshold",     0.50)),
        max_threshold     = float(sc.get("max_threshold",     0.82)),
        target_fpr        = float(sc.get("target_fpr",        0.15)),
        target_accuracy   = float(sc.get("target_accuracy",   0.75)),
        max_iterations    = int(  sc.get("max_iterations",    30)),
        aggregation       = str(  sc.get("aggregation",       "max_pool")),
        category_weights  = {k: float(v) for k, v in dw.items()},
    )


# ─── Result Type ──────────────────────────────────────────────────────────────

@dataclass
class ScoringResult:
    """
    Final scoring output for one URL.

    Consumed by reporter.py (Phase 7).

    Attributes:
        url:                 Scanned URL.
        category_scores:     Adjusted per-category scores after analyser bonuses.
        composite_score:     Final aggregated score [0, 1].
        severity:            Severity enum derived from composite_score.
        label:               Binary classification relative to active threshold.
        confidence:          Normalised confidence estimate [0, 1].
        dominant_category:   Category driving the composite score (or None).
        analyser_bonuses:    Breakdown of analyser bonus contributions.
        threshold_used:      Threshold value applied for label assignment.
        detection_result:    Source DetectionResult (pass-through for reporter).
        analysis_result:     Source AnalysisResult (pass-through for reporter).
    """
    url:               str
    category_scores:   dict[str, float]
    composite_score:   float
    severity:          Severity
    label:             Label
    confidence:        float
    dominant_category: str | None
    analyser_bonuses:  dict[str, float]
    threshold_used:    float
    detection_result:  DetectionResult
    analysis_result:   AnalysisResult


# ─── Scorer ───────────────────────────────────────────────────────────────────

class Scorer:
    """
    Weighted vulnerability scoring engine.

    Merges DetectionResult and AnalysisResult into a ScoringResult with
    severity label and binary classification.

    The active threshold starts at config.initial_threshold and can be
    updated via update_threshold() after each scan batch (Algorithm 2).

    Args:
        config: Full settings dict (from utils.load_config).
    """

    def __init__(self, config: dict) -> None:
        self._cfg = _parse_config(config)
        self._threshold = self._cfg.initial_threshold

        global _log
        _log = get_logger(__name__, config)
        _log.debug(
            "Scorer initialised: threshold=%.3f aggregation=%s",
            self._threshold, self._cfg.aggregation,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def threshold(self) -> float:
        """Current active classification threshold."""
        return self._threshold

    def score(
        self,
        detection: DetectionResult,
        analysis:  AnalysisResult,
    ) -> ScoringResult:
        """
        Produce a ScoringResult from one (DetectionResult, AnalysisResult) pair.

        Args:
            detection: Output of Detector.analyse().
            analysis:  Output of Analyser.analyse() for the same URL.

        Returns:
            ScoringResult with all scoring fields populated.
        """
        # 1. Compute per-category analyser bonuses
        bonuses = self._compute_bonuses(detection, analysis)

        # 2. Adjust detection scores with bonuses and category weights
        adjusted = self._adjust_scores(detection.category_scores, bonuses)

        # 3. Aggregate to composite score
        composite = self._aggregate(adjusted)

        # 4. Derive severity and binary label
        severity   = _severity(composite)
        label      = Label.VULNERABLE if composite >= self._threshold else Label.BENIGN
        confidence = _confidence(composite, self._threshold)

        # 5. Dominant category on adjusted scores
        dominant = (
            max(adjusted, key=lambda k: adjusted[k])
            if any(v > 0.0 for v in adjusted.values())
            else None
        )

        _log.debug(
            "%s → composite=%.4f severity=%s label=%s",
            detection.url, composite, severity.value, label.value,
        )

        return ScoringResult(
            url               = detection.url,
            category_scores   = adjusted,
            composite_score   = round(composite, 6),
            severity          = severity,
            label             = label,
            confidence        = round(confidence, 4),
            dominant_category = dominant,
            analyser_bonuses  = bonuses,
            threshold_used    = self._threshold,
            detection_result  = detection,
            analysis_result   = analysis,
        )

    def score_many(
        self,
        pairs: list[tuple[DetectionResult, AnalysisResult]],
    ) -> list[ScoringResult]:
        """
        Score a batch of (DetectionResult, AnalysisResult) pairs.

        Args:
            pairs: Paired outputs from Detector and Analyser for each URL.

        Returns:
            List of ScoringResult in the same order as input.
        """
        results = [self.score(det, ana) for det, ana in pairs]
        flagged = sum(1 for r in results if r.label == Label.VULNERABLE)
        _log.info(
            "Batch scoring complete: %d/%d URLs labelled VULNERABLE (threshold=%.3f).",
            flagged, len(results), self._threshold,
        )
        return results

    def update_threshold(
        self,
        observed_fpr:      float,
        observed_accuracy: float,
    ) -> float:
        """
        Adaptive threshold update (Algorithm 2 from the paper).

        Adjusts the threshold up or down by a fixed step based on
        whether the observed FPR and accuracy meet their targets.
        The new threshold is clamped to [min_threshold, max_threshold].

        This method is called by the integration layer (Phase 9) after
        each scan batch when ground-truth labels are available.

        Args:
            observed_fpr:      False-positive rate observed in the last batch.
            observed_accuracy: Classification accuracy observed in the last batch.

        Returns:
            Updated threshold value.
        """
        cfg  = self._cfg
        step = 0.01  # fixed step size — keeps updates conservative

        old = self._threshold
        if observed_fpr > cfg.target_fpr:
            # Too many false positives — raise threshold to tighten classification
            self._threshold = min(cfg.max_threshold, self._threshold + step)
        elif observed_accuracy < cfg.target_accuracy:
            # Accuracy below target — lower threshold to recover true positives
            self._threshold = max(cfg.min_threshold, self._threshold - step)
        # else: both targets met — leave threshold unchanged

        if self._threshold != old:
            _log.info(
                "Threshold updated: %.3f → %.3f (fpr=%.3f acc=%.3f)",
                old, self._threshold, observed_fpr, observed_accuracy,
            )
        return self._threshold

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _compute_bonuses(
        self,
        detection: DetectionResult,
        analysis:  AnalysisResult,
    ) -> dict[str, float]:
        """
        Compute additive bonus contributions from AnalysisResult signals.

        Bonuses are small and capped to prevent structural signals from
        dominating the composite score in the absence of detection evidence.

        Returns:
            Dict of category → bonus float (may be 0.0 for most categories).
        """
        bonuses: dict[str, float] = {cat: 0.0 for cat in detection.category_scores}

        # ── Header bonus → affects all categories via a shared pool ──────────
        # Distribute header weakness signal to whichever category is dominant.
        n_missing   = min(len(analysis.headers.missing),   4)
        n_insecure  = min(len(analysis.headers.insecure_values), 3)
        header_bonus = (
            n_missing  * _HEADER_MISSING_BONUS +
            n_insecure * _HEADER_INSECURE_BONUS
        )
        # Assign header bonus to the dominant detection category (or admin by default)
        target_cat = detection.dominant_category or "admin"
        if target_cat in bonuses:
            bonuses[target_cat] = round(bonuses[target_cat] + header_bonus, 6)

        # ── Login bonus → password form on suspicious action ──────────────────
        for form in analysis.forms:
            if form.has_password_field and form.action_path_suspicious:
                bonuses["login"] = round(
                    bonuses.get("login", 0.0) + _PASSWORD_FORM_BONUS, 6
                )
                break  # one bonus per page

        # ── XSS bonus → suspicious inline JS patterns ─────────────────────────
        js_hits = min(len(analysis.scripts.suspicious_pattern_hits), 2)
        if js_hits:
            bonuses["xss"] = round(
                bonuses.get("xss", 0.0) + js_hits * _JS_PATTERN_BONUS, 6
            )

        # ── Keyword bonus → sensitive keywords boost dominant category ─────────
        kw_hits = min(len(analysis.keywords.found), 3)
        if kw_hits and detection.dominant_category:
            dc = detection.dominant_category
            bonuses[dc] = round(bonuses.get(dc, 0.0) + kw_hits * _KEYWORD_BONUS, 6)

        return bonuses

    def _adjust_scores(
        self,
        category_scores: dict[str, float],
        bonuses:         dict[str, float],
    ) -> dict[str, float]:
        """
        Apply category weight multipliers and analyser bonuses.

        Final per-category score = min(1.0,
            detection_score * weight + bonus
        )

        Args:
            category_scores: Normalised detection scores per category.
            bonuses:         Analyser bonus per category from _compute_bonuses.

        Returns:
            Adjusted score dict, all values in [0, 1].
        """
        adjusted: dict[str, float] = {}
        for cat, score in category_scores.items():
            weight = self._cfg.category_weights.get(cat, 1.0)
            bonus  = bonuses.get(cat, 0.0)
            adjusted[cat] = round(min(1.0, score * weight + bonus), 6)
        return adjusted

    def _aggregate(self, adjusted: dict[str, float]) -> float:
        """
        Aggregate per-category scores to a single composite score.

        Supports two modes from settings.yaml[scoring.aggregation]:
          max_pool    — maximum across categories (paper default, Algorithm 1)
          weighted_avg — mean of all category scores (future ML integration)

        Args:
            adjusted: Per-category adjusted scores.

        Returns:
            Composite score in [0, 1].
        """
        if not adjusted:
            return 0.0
        if self._cfg.aggregation == "weighted_avg":
            return round(sum(adjusted.values()) / len(adjusted), 6)
        # Default: max_pool
        return round(max(adjusted.values()), 6)


# ─── Pure functions ───────────────────────────────────────────────────────────

def _severity(composite: float) -> Severity:
    """
    Map a composite score to a Severity label.

    Args:
        composite: Composite score in [0, 1].

    Returns:
        Severity enum value.
    """
    for threshold, severity in _SEVERITY_BANDS:
        if composite >= threshold:
            return severity
    return Severity.NONE


def _confidence(composite: float, threshold: float) -> float:
    """
    Estimate classification confidence from score distance to threshold.

    Confidence reflects how far the composite score is from the decision
    boundary, normalised to [0, 1].  A score at the threshold returns
    0.5 (maximum uncertainty); scores near 0 or 1 return near-0 or near-1.

    Formula: confidence = 0.5 + 0.5 * tanh(k * (composite - threshold))
    where k=6 gives a moderate sigmoid slope without claiming certainty.

    Args:
        composite: Composite score in [0, 1].
        threshold: Active classification threshold.

    Returns:
        Confidence float in [0, 1].
    """
    import math
    k = 6.0
    return round(0.5 + 0.5 * math.tanh(k * (composite - threshold)), 4)
