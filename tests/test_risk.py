"""
Tests for the Risk Scoring module.

Tests cover:
- Empty findings (score = 0)
- Category caps respected
- Score always 0-100
- Deterministic scoring
- Boundary conditions
- Maximum possible score
- Threshold mapping
"""

import pytest
from app.security.risk import (
    calculate_risk_score,
    CATEGORY_MAX_POINTS,
    get_risk_thresholds,
    get_category_limits,
)
from app.core.models import Finding, ScoreBreakdown


class TestRiskScoreBasics:
    """Basic risk score functionality tests."""

    def test_empty_findings_score_zero(self):
        """Test that empty findings produce score 0."""
        result = calculate_risk_score([])
        assert result.total_score == 0
        assert result.risk_level == "low"
        # All categories should be 0
        for cat in CATEGORY_MAX_POINTS:
            assert getattr(result.score_breakdown, cat) == 0

    def test_single_finding_adds_score(self):
        """Test that a single finding adds its severity to score."""
        findings = [
            Finding(
                rule_id="PI-001",
                category="instruction_override",
                source="user_message",
                reason="Test",
                severity=8,
            )
        ]
        result = calculate_risk_score(findings)
        assert result.total_score == 8
        assert result.score_breakdown.instruction_override == 8
        # Other categories remain 0
        assert result.score_breakdown.sensitive_data_extraction == 0

    def test_multiple_findings_same_category_sum(self):
        """Test multiple findings in same category sum up."""
        findings = [
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=8),
            Finding(rule_id="PI-002", category="instruction_override", source="user_message", reason="Test", severity=7),
            Finding(rule_id="PI-003", category="instruction_override", source="user_message", reason="Test", severity=7),
        ]
        result = calculate_risk_score(findings)
        # 8 + 7 + 7 = 22, under cap of 25
        assert result.total_score == 22
        assert result.score_breakdown.instruction_override == 22

    def test_category_cap_respected(self):
        """Test that category caps are enforced."""
        # Create findings that would exceed the 25 cap for instruction_override
        findings = [
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=10),
            Finding(rule_id="PI-002", category="instruction_override", source="user_message", reason="Test", severity=10),
            Finding(rule_id="PI-003", category="instruction_override", source="user_message", reason="Test", severity=10),
            Finding(rule_id="PI-004", category="instruction_override", source="user_message", reason="Test", severity=10),
        ]
        result = calculate_risk_score(findings)
        # Total severity = 40, but cap is 25
        assert result.score_breakdown.instruction_override == 25
        assert result.total_score == 25


class TestAllCategoryCaps:
    """Test each category's cap independently."""

    def test_instruction_override_cap_25(self):
        findings = [Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=30)]
        result = calculate_risk_score(findings)
        assert result.score_breakdown.instruction_override == 25

    def test_sensitive_data_extraction_cap_25(self):
        findings = [Finding(rule_id="PI-010", category="sensitive_data_extraction", source="user_message", reason="Test", severity=30)]
        result = calculate_risk_score(findings)
        assert result.score_breakdown.sensitive_data_extraction == 25

    def test_role_tool_manipulation_cap_20(self):
        findings = [Finding(rule_id="PI-020", category="role_tool_manipulation", source="user_message", reason="Test", severity=25)]
        result = calculate_risk_score(findings)
        assert result.score_breakdown.role_tool_manipulation == 20

    def test_obfuscation_cap_10(self):
        findings = [Finding(rule_id="PI-030", category="obfuscation", source="user_message", reason="Test", severity=15)]
        result = calculate_risk_score(findings)
        assert result.score_breakdown.obfuscation == 10

    def test_suspicious_external_instruction_cap_10(self):
        findings = [Finding(rule_id="PI-040", category="suspicious_external_instruction", source="pdf", reason="Test", severity=15)]
        result = calculate_risk_score(findings)
        assert result.score_breakdown.suspicious_external_instruction == 10

    def test_security_bypass_cap_10(self):
        findings = [Finding(rule_id="PI-050", category="security_bypass", source="user_message", reason="Test", severity=15)]
        result = calculate_risk_score(findings)
        assert result.score_breakdown.security_bypass == 10


class TestMaximumScore:
    """Test maximum possible score (all categories at cap = 100)."""

    def test_all_categories_at_max_equals_100(self):
        """Test that hitting all caps gives score 100."""
        findings = [
            # instruction_override: 25
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=25),
            # sensitive_data_extraction: 25
            Finding(rule_id="PI-010", category="sensitive_data_extraction", source="user_message", reason="Test", severity=25),
            # role_tool_manipulation: 20
            Finding(rule_id="PI-020", category="role_tool_manipulation", source="user_message", reason="Test", severity=20),
            # obfuscation: 10
            Finding(rule_id="PI-030", category="obfuscation", source="user_message", reason="Test", severity=10),
            # suspicious_external_instruction: 10
            Finding(rule_id="PI-040", category="suspicious_external_instruction", source="pdf", reason="Test", severity=10),
            # security_bypass: 10
            Finding(rule_id="PI-050", category="security_bypass", source="user_message", reason="Test", severity=10),
        ]
        result = calculate_risk_score(findings)
        assert result.total_score == 100
        assert result.risk_level == "critical"

    def test_score_never_exceeds_100(self):
        """Test that even with massive severity, score caps at 100 (sum of all caps)."""
        findings = [
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=100),
            Finding(rule_id="PI-010", category="sensitive_data_extraction", source="user_message", reason="Test", severity=100),
            Finding(rule_id="PI-020", category="role_tool_manipulation", source="user_message", reason="Test", severity=100),
            Finding(rule_id="PI-030", category="obfuscation", source="user_message", reason="Test", severity=100),
            Finding(rule_id="PI-040", category="suspicious_external_instruction", source="pdf", reason="Test", severity=100),
            Finding(rule_id="PI-050", category="security_bypass", source="user_message", reason="Test", severity=100),
        ]
        result = calculate_risk_score(findings)
        # Max possible = 25 + 25 + 20 + 10 + 10 + 10 = 100
        assert result.total_score == 100


class TestDeterministicScoring:
    """Test that same input always produces same score."""

    def test_same_findings_same_score(self):
        """Test deterministic scoring."""
        findings = [
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=8),
            Finding(rule_id="PI-010", category="sensitive_data_extraction", source="user_message", reason="Test", severity=7),
        ]
        result1 = calculate_risk_score(findings)
        result2 = calculate_risk_score(findings)
        assert result1.total_score == result2.total_score
        assert result1.risk_level == result2.risk_level
        assert result1.score_breakdown == result2.score_breakdown

    def test_order_independent(self):
        """Test that finding order doesn't affect score."""
        findings_a = [
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=8),
            Finding(rule_id="PI-010", category="sensitive_data_extraction", source="user_message", reason="Test", severity=7),
        ]
        findings_b = [
            Finding(rule_id="PI-010", category="sensitive_data_extraction", source="user_message", reason="Test", severity=7),
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=8),
        ]
        result_a = calculate_risk_score(findings_a)
        result_b = calculate_risk_score(findings_b)
        assert result_a.total_score == result_b.total_score


class TestRiskLevelThresholds:
    """Test risk level mapping with default thresholds."""

    def test_low_threshold(self):
        """Test scores below 30 are 'low'."""
        findings = [Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=10)]
        result = calculate_risk_score(findings)
        assert result.risk_level == "low"

    def test_medium_threshold(self):
        """Test scores 30-59 are 'medium'."""
        # Single finding at max cap reaches 25, need more from other categories to reach 30
        findings = [
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=25),
            Finding(rule_id="PI-010", category="sensitive_data_extraction", source="user_message", reason="Test", severity=5),
        ]
        result = calculate_risk_score(findings)
        assert result.total_score == 30  # 25 (capped) + 5 = 30
        assert result.risk_level == "medium"

    def test_high_threshold(self):
        """Test scores 60-79 are 'high'."""
        findings = [
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=25),
            Finding(rule_id="PI-010", category="sensitive_data_extraction", source="user_message", reason="Test", severity=25),
            Finding(rule_id="PI-020", category="role_tool_manipulation", source="user_message", reason="Test", severity=10),
        ]
        result = calculate_risk_score(findings)
        assert result.total_score == 60
        assert result.risk_level == "high"

    def test_critical_threshold(self):
        """Test scores 80+ are 'critical'."""
        findings = [
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=25),
            Finding(rule_id="PI-010", category="sensitive_data_extraction", source="user_message", reason="Test", severity=25),
            Finding(rule_id="PI-020", category="role_tool_manipulation", source="user_message", reason="Test", severity=20),
            Finding(rule_id="PI-030", category="obfuscation", source="user_message", reason="Test", severity=10),
        ]
        result = calculate_risk_score(findings)
        assert result.total_score == 80
        assert result.risk_level == "critical"

    def test_boundary_exact_30(self):
        """Test exact boundary at 30 is medium."""
        findings = [
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=25),
            Finding(rule_id="PI-002", category="instruction_override", source="user_message", reason="Test", severity=5),
        ]
        result = calculate_risk_score(findings)
        # Category cap of 25 applies per category; PI-001 fills it. PI-002 also maps to instruction_override but capped.
        # So total = 25 (PI-001) + 0 (PI-002 capped) = 25, which is low
        # For 30, we need findings from DIFFERENT categories
        findings2 = [
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=25),
            Finding(rule_id="PI-010", category="sensitive_data_extraction", source="user_message", reason="Test", severity=5),
        ]
        result2 = calculate_risk_score(findings2)
        assert result2.total_score == 30
        assert result2.risk_level == "medium"

    def test_boundary_exact_60(self):
        """Test exact boundary at 60 is high."""
        findings = [
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=25),
            Finding(rule_id="PI-010", category="sensitive_data_extraction", source="user_message", reason="Test", severity=25),
            Finding(rule_id="PI-020", category="role_tool_manipulation", source="user_message", reason="Test", severity=10),
        ]
        result = calculate_risk_score(findings)
        assert result.total_score == 60
        assert result.risk_level == "high"

    def test_boundary_exact_80(self):
        """Test exact boundary at 80 is critical."""
        findings = [
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=25),
            Finding(rule_id="PI-010", category="sensitive_data_extraction", source="user_message", reason="Test", severity=25),
            Finding(rule_id="PI-020", category="role_tool_manipulation", source="user_message", reason="Test", severity=20),
            Finding(rule_id="PI-030", category="obfuscation", source="user_message", reason="Test", severity=10),
        ]
        result = calculate_risk_score(findings)
        assert result.total_score == 80
        assert result.risk_level == "critical"


class TestScoreBreakdownStructure:
    """Test that score breakdown has correct structure."""

    def test_all_categories_present(self):
        """Test all six categories in breakdown."""
        result = calculate_risk_score([])
        categories = [
            "instruction_override",
            "sensitive_data_extraction",
            "role_tool_manipulation",
            "obfuscation",
            "suspicious_external_instruction",
            "security_bypass",
        ]
        for cat in categories:
            assert hasattr(result.score_breakdown, cat)
            assert isinstance(getattr(result.score_breakdown, cat), int)

    def test_breakdown_values_never_negative(self):
        """Test breakdown values are never negative (capped at 0)."""
        # Findings with negative severity shouldn't reduce score below 0
        # (Finding model validation prevents negative severity, but test the logic)
        findings = [
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=5),
        ]
        result = calculate_risk_score(findings)
        for cat in CATEGORY_MAX_POINTS:
            val = getattr(result.score_breakdown, cat)
            assert val >= 0

        # Test that total score is never negative
        assert result.total_score >= 0


class TestConfigHelpers:
    """Test configuration helper functions."""

    def test_get_risk_thresholds(self):
        """Test thresholds config function."""
        thresholds = get_risk_thresholds()
        assert "low" in thresholds
        assert "medium" in thresholds
        assert "high" in thresholds
        assert "critical" in thresholds
        # Critical is the same as high threshold (>= 80)
        assert thresholds["critical"] == thresholds["high"]

    def test_get_category_limits(self):
        """Test category limits config function."""
        limits = get_category_limits()
        assert limits == CATEGORY_MAX_POINTS
        # Should be a copy, not the original
        limits["instruction_override"] = 999
        assert CATEGORY_MAX_POINTS["instruction_override"] == 25


class TestRealisticScenarios:
    """Test realistic detection scenarios."""

    def test_benign_message_low_score(self):
        """Benign message with minor findings stays low."""
        findings = [
            Finding(rule_id="PI-033", category="obfuscation", source="user_message", reason="Test", severity=3),
        ]
        result = calculate_risk_score(findings)
        assert result.total_score == 3
        assert result.risk_level == "low"

    def test_multiple_categories_sum(self):
        """Findings from multiple categories sum correctly."""
        findings = [
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=8),
            Finding(rule_id="PI-010", category="sensitive_data_extraction", source="user_message", reason="Test", severity=8),
            Finding(rule_id="PI-030", category="obfuscation", source="user_message", reason="Test", severity=5),
        ]
        result = calculate_risk_score(findings)
        assert result.total_score == 21  # 8 + 8 + 5
        assert result.risk_level == "low"

    def test_direct_vs_indirect_sources(self):
        """Test that source doesn't affect scoring, only category."""
        findings_user = [
            Finding(rule_id="PI-001", category="instruction_override", source="user_message", reason="Test", severity=8),
        ]
        findings_pdf = [
            Finding(rule_id="PI-001", category="instruction_override", source="pdf", reason="Test", severity=8),
        ]
        result_user = calculate_risk_score(findings_user)
        result_pdf = calculate_risk_score(findings_pdf)
        assert result_user.total_score == result_pdf.total_score
        assert result_user.score_breakdown.instruction_override == result_pdf.score_breakdown.instruction_override