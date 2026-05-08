"""
risk_classifier.py — Converts raw detection signals into a normalized
risk score, risk level, and structured output.

The scoring approach is intentionally simple:
- Sum all signal weights
- Normalize against a calibrated max (empirically set to ~60 based on
  a few dozen test messages — may need tuning with more data)
- Clamp to 0–100
- Bucket into low/medium/high using fixed thresholds

TODO: The normalization max is a rough heuristic. With a labelled dataset
we could calibrate this more rigorously (e.g. set max = 99th percentile
of scam message scores). For now 60 works reasonably well.
"""

from dataclasses import dataclass, field
from typing import List, Dict
from detector import DetectionResult, DetectionSignal


# ---------------------------------------------------------------------------
# Thresholds — easy to tune here without touching scoring logic
# ---------------------------------------------------------------------------

RISK_THRESHOLDS = {
    "low": (0, 30),      # 0–29 = low
    "medium": (30, 60),  # 30–59 = medium
    "high": (60, 101),   # 60–100 = high
}

# Normalization ceiling — scores above this get clamped to 100
# Based on empirical testing: a heavily layered scam message typically
# scores around 55–80 raw points.
SCORE_NORMALIZATION_MAX = 65.0


# ---------------------------------------------------------------------------
# Output structure
# ---------------------------------------------------------------------------

@dataclass
class RiskAssessment:
    risk_score: int                        # 0–100
    risk_level: str                        # low / medium / high
    detected_categories: List[str]         # unique categories triggered
    explanation: str                       # human-readable summary
    signal_breakdown: List[Dict]           # per-signal detail (for debugging/transparency)
    raw_score: float                       # unnormalized sum (useful for inspection)


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

def classify(detection_result: DetectionResult) -> RiskAssessment:
    """
    Take a DetectionResult and produce a final RiskAssessment.
    """
    signals = detection_result.signals
    raw_score = detection_result.raw_score

    # Normalize to 0–100
    normalized = min(100, int((raw_score / SCORE_NORMALIZATION_MAX) * 100))

    # Risk level
    risk_level = _score_to_level(normalized)

    # Unique categories (preserve insertion order, deduplicate)
    seen = set()
    categories = []
    for s in signals:
        if s.category not in seen:
            seen.add(s.category)
            categories.append(s.category)

    # Build explanation
    explanation = _build_explanation(categories, signals, normalized)

    # Signal breakdown for API transparency
    breakdown = [
        {
            "category": s.category,
            "weight": s.weight,
            "matched": s.matched_text,
            "reason": s.explanation,
        }
        for s in signals
    ]

    return RiskAssessment(
        risk_score=normalized,
        risk_level=risk_level,
        detected_categories=categories,
        explanation=explanation,
        signal_breakdown=breakdown,
        raw_score=raw_score,
    )


def _score_to_level(score: int) -> str:
    for level, (low, high) in RISK_THRESHOLDS.items():
        if low <= score < high:
            return level
    return "high"  # safety fallback


def _build_explanation(
    categories: List[str],
    signals: List[DetectionSignal],
    score: int,
) -> str:
    """
    Generate a short plain-English explanation of why the message scored
    as it did. Deliberately kept simple.
    """
    if not categories:
        return "No fraud indicators detected. Message appears benign."

    # Pick the top 3 signals by weight for the summary
    top_signals = sorted(signals, key=lambda s: s.weight, reverse=True)[:3]
    top_reasons = [s.explanation for s in top_signals]

    cat_count = len(categories)
    cat_display = ", ".join(categories[:4])
    if cat_count > 4:
        cat_display += f" (+{cat_count - 4} more)"

    reasons_display = "; ".join(top_reasons)

    if score >= 60:
        severity_note = "Multiple high-confidence fraud patterns detected."
    elif score >= 30:
        severity_note = "Some suspicious patterns present — treat with caution."
    else:
        severity_note = "Weak signals detected — likely benign but worth noting."

    return (
        f"{severity_note} "
        f"Triggered categories: {cat_display}. "
        f"Top signals: {reasons_display}."
    )


# ---------------------------------------------------------------------------
# Convenience: full pipeline in one call
# ---------------------------------------------------------------------------

def assess_message(message: str) -> RiskAssessment:
    """
    One-shot: run detection + classification. Import this in app.py.
    """
    from detector import analyze_message
    detection = analyze_message(message)
    return classify(detection)


# ---------------------------------------------------------------------------
# Quick smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    samples = [
        "Your BVN has been flagged. Send your OTP immediately or your account will be suspended.",
        "Hi, I just wanted to check if we're still on for lunch tomorrow?",
        "Invest just ₦5,000 and earn ₦50,000 weekly. Guaranteed returns. Contact me on WhatsApp.",
        "You have won a lucky prize from MTN promo! Claim your reward now. Limited time offer.",
    ]

    for msg in samples:
        result = assess_message(msg)
        print(f"\nMessage: {msg[:70]}...")
        print(f"  Score: {result.risk_score} | Level: {result.risk_level}")
        print(f"  Categories: {result.detected_categories}")
        print(f"  Explanation: {result.explanation[:100]}")
