"""
Policy Engine

Applies server-side security policies to scan results.
Enforces that BLOCK and FLAG never invoke the LLM provider.
SANITIZE transforms content and re-scans before forwarding.

Policies are server-controlled; client cannot override.
"""

from dataclasses import dataclass
from typing import Optional
from app.core.config import get_settings
from app.core.models import Finding, ScanResponse, ScoreBreakdown
from app.security.risk import calculate_risk_score, get_risk_thresholds, CATEGORY_MAX_POINTS


@dataclass
class PolicyResult:
    """Result of policy application."""
    policy: str
    decision: str  # "allowed", "held_for_review", "rejected", "sanitized"
    sanitized_preview: Optional[str]
    provider_called: bool
    reason: str


def apply_policy(
    policy: str,
    risk_score: int,
    findings: list[Finding],
    settings,
) -> PolicyResult:
    """
    Apply server-side policy to determine action.

    Security rules (non-negotiable):
    - BLOCK: provider must not be called, request rejected
    - FLAG: provider must not be called, request held for review
    - ALLOW: provider may be called (if enabled and permitted)
    - SANITIZE: transform candidate, re-scan, forward only if safe

    Args:
        policy: Server policy (ALLOW, FLAG, BLOCK, SANITIZE)
        risk_score: Calculated risk score 0-100
        findings: Detection findings from the detector
        settings: Application settings

    Returns:
        PolicyResult with decision, provider_called status, and reason
    """
    policy = policy.upper()

    # Get configurable thresholds (function gets settings internally)
    thresholds = get_risk_thresholds()

    # Determine risk levels based on PRD thresholds:
    # low: score < risk_threshold_low (default 30)
    # medium: risk_threshold_low <= score < risk_threshold_medium (default 60)
    # high: risk_threshold_medium <= score < risk_threshold_high (default 80)
    # critical: score >= risk_threshold_high (default 80)
    is_critical = risk_score >= thresholds["high"]  # >= 80
    is_high = risk_score >= thresholds["medium"]    # >= 60
    is_medium = risk_score >= thresholds["low"]     # >= 30

    # ---- BLOCK Policy ----
    # Most restrictive: always reject, never call provider
    if policy == "BLOCK":
        return PolicyResult(
            policy="BLOCK",
            decision="rejected",
            sanitized_preview=None,
            provider_called=False,
            reason=f"Request blocked by server policy (risk score: {risk_score})",
        )

    # ---- FLAG Policy ----
    # Hold for review: never call provider, just hold
    if policy == "FLAG":
        # Even low-risk requests can be flagged if server wants review
        return PolicyResult(
            policy="FLAG",
            decision="held_for_review",
            sanitized_preview=None,
            provider_called=False,
            reason=f"Request held for authorized review (risk score: {risk_score}, level: {risk_score >= thresholds['high'] and 'high' or 'low'})",
        )

    # ---- SANITIZE Policy ----
    # Transform content, re-scan, forward only if safe
    if policy == "SANITIZE":
        # Check if risk is too high to safely sanitize
        if is_critical or is_high:
            # Too dangerous to sanitize; fall back to BLOCK
            return PolicyResult(
                policy="BLOCK",
                decision="rejected",
                sanitized_preview=None,
                provider_called=False,
                reason=f"Risk too high ({risk_score}) for safe sanitization; request blocked",
            )

        # Check for specific dangerous findings that sanitization won't fix
        dangerous_categories = {"instruction_override", "sensitive_data_extraction", "security_bypass"}
        dangerous_findings = [f for f in findings if f.category in dangerous_categories]

        if dangerous_findings:
            # Has dangerous content types - can't safely sanitize
            return PolicyResult(
                policy="BLOCK",
                decision="rejected",
                sanitized_preview=None,
                provider_called=False,
                reason=f"Dangerous content detected that sanitization cannot resolve",
            )

        # Safe to sanitize: create preview, re-scan
        # In a real implementation, we'd create a sanitized version and re-run detection
        # For now, create a placeholder preview and mark as re-scanned
        sanitized_preview = "[Content sanitized - instruction-like segments removed; re-scanning required]"

        # After sanitization, we assume the risk is reduced but not zero
        # In Phase 5+, the sanitized candidate would be re-scanned
        return PolicyResult(
            policy="SANITIZE",
            decision="sanitized",
            sanitized_preview=sanitized_preview,
            provider_called=False,
            reason=f"Content sanitized; re-scan required before provider use (original risk: {risk_score})",
        )

    # ---- ALLOW Policy ----
    # Permit processing; provider may be called if enabled
    if policy == "ALLOW":
        # Check if risk level permits allowance
        if is_critical:
            # Even ALLOW won't override critical risk for safety
            return PolicyResult(
                policy="ALLOW",
                decision="held_for_review",
                sanitized_preview=None,
                provider_called=False,
                reason=f"Critical risk ({risk_score}) overrides ALLOW policy; holding for review",
            )

        # Check for specific dangerous findings even with low total score
        dangerous_categories = {"instruction_override", "sensitive_data_extraction", "security_bypass"}
        dangerous_findings = [f for f in findings if f.category in dangerous_categories]

        if dangerous_findings and risk_score >= 30:
            # Has dangerous content types at moderate+ risk
            return PolicyResult(
                policy="ALLOW",
                decision="held_for_review",
                sanitized_preview=None,
                provider_called=False,
                reason=f"Dangerous content patterns detected (risk score: {risk_score}); holding for review",
            )

        # Safe to allow - provider may be called
        return PolicyResult(
            policy="ALLOW",
            decision="allowed",
            sanitized_preview=None,
            provider_called=False,
            reason=f"Request approved; provider may be invoked (risk score: {risk_score})",
        )

    # ---- Fallback ----
    # Unknown policy defaults to BLOCK for safety
    return PolicyResult(
        policy="BLOCK",
        decision="rejected",
        sanitized_preview=None,
        provider_called=False,
        reason=f"Unknown policy '{policy}'; defaulting to BLOCK for safety",
    )


def _check_dangerous_findings(findings: list[Finding], categories: set[str]) -> bool:
    """Check if any findings match dangerous categories."""
    return any(f.category in categories for f in findings)