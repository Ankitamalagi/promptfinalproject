"""
Risk Scoring Module

Calculates a 0-100 risk score from detector findings with category caps.
This is a heuristic indicator, NOT a calibrated probability.
"""

from dataclasses import dataclass
from typing import Optional
from app.core.models import ScoreBreakdown, Finding
from app.core.config import get_settings


# Category configuration from PRD
# Maximum contribution per category
CATEGORY_MAX_POINTS = {
    "instruction_override": 25,
    "sensitive_data_extraction": 25,
    "role_tool_manipulation": 20,
    "obfuscation": 10,
    "suspicious_external_instruction": 10,
    "security_bypass": 10,
}

# Default thresholds for risk levels (configurable via settings)
DEFAULT_THRESHOLDS = {
    "low": 30,      # 0-29
    "medium": 60,   # 30-59
    "high": 80,     # 60-79
    "critical": 100,  # 80-100
}


@dataclass
class RiskScoreResult:
    """Result of risk score calculation."""
    total_score: int
    risk_level: str
    score_breakdown: ScoreBreakdown


def calculate_risk_score(findings: list[Finding]) -> RiskScoreResult:
    """
    Calculate risk score from detector findings.

    Args:
        findings: List of findings from the detector

    Returns:
        RiskScoreResult with total score, risk level, and category breakdown
    """
    settings = get_settings()

    # Initialize breakdown with zeros
    breakdown = ScoreBreakdown()

    # Track accumulated points per category (before capping)
    category_totals = {cat: 0 for cat in CATEGORY_MAX_POINTS}

    # Sum severity per category
    for finding in findings:
        if finding.category in category_totals:
            category_totals[finding.category] += finding.severity

    # Apply category caps and populate breakdown
    total_score = 0
    for category, max_points in CATEGORY_MAX_POINTS.items():
        capped_value = min(category_totals[category], max_points)
        # Set the value on the breakdown model
        setattr(breakdown, category, capped_value)
        total_score += capped_value

    # Ensure score is within 0-100
    total_score = max(0, min(total_score, 100))

    # Determine risk level using configurable thresholds
    risk_level = _score_to_risk_level(total_score, settings)

    return RiskScoreResult(
        total_score=total_score,
        risk_level=risk_level,
        score_breakdown=breakdown,
    )


def _score_to_risk_level(score: int, settings) -> str:
    """
    Map numeric score to risk level using configurable thresholds.

    Thresholds from settings (with defaults):
    - low: score < risk_threshold_low (default 30)
    - medium: risk_threshold_low <= score < risk_threshold_medium (default 60)
    - high: risk_threshold_medium <= score < risk_threshold_high (default 80)
    - critical: score >= risk_threshold_high (default 80)
    """
    if score >= settings.risk_threshold_high:
        return "critical"
    elif score >= settings.risk_threshold_medium:
        return "high"
    elif score >= settings.risk_threshold_low:
        return "medium"
    else:
        return "low"


def get_risk_thresholds() -> dict:
    """Get current risk thresholds from settings (for /api/config)."""
    settings = get_settings()
    return {
        "low": settings.risk_threshold_low,
        "medium": settings.risk_threshold_medium,
        "high": settings.risk_threshold_high,
        "critical": settings.risk_threshold_high,
    }


def get_category_limits() -> dict:
    """Get category maximum points (for documentation/config)."""
    return CATEGORY_MAX_POINTS.copy()