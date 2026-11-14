"""
Rule-based Prompt Injection Detector

This module implements deterministic detection rules for prompt injection indicators.
Each rule has a unique ID, category, and returns explainable findings.

IMPORTANT: These are heuristic indicators, NOT proof of attack.
A single phrase match does not confirm an attack - context matters.
"""

import re
from dataclasses import dataclass
from typing import Optional
from app.core.models import Finding
from app.security.normalizer import NormalizedInput


@dataclass
class DetectionRule:
    """
    Represents a single detection rule.

    Attributes:
        rule_id: Unique identifier (e.g., "PI-001")
        category: Risk category (matches ScoreBreakdown categories)
        pattern: Compiled regex pattern to match
        reason: Human-readable explanation of what this rule detects
        severity: Weight/points this finding contributes (1-10)
        source_field: Which input field this rule applies to ("user_message", "retrieved_content", or "both")
    """
    rule_id: str
    category: str
    pattern: re.Pattern
    reason: str
    severity: int
    source_field: str  # "user_message", "retrieved_content", or "both"


# ============================================================================
# DETECTION RULES
# ============================================================================
# Each rule is documented with what it detects and why.
# Rules are grouped by PRD risk categories.
# Maximum points per category (from PRD):
# - instruction_override: 25
# - sensitive_data_extraction: 25
# - role_tool_manipulation: 20
# - obfuscation: 10
# - suspicious_external_instruction: 10
# - security_bypass: 10

DETECTION_RULES: list[DetectionRule] = [
    # -------------------------------------------------------------------------
    # CATEGORY: instruction_override (max 25 points)
    # Detects attempts to override or ignore system/application instructions
    # -------------------------------------------------------------------------
    DetectionRule(
        rule_id="PI-001",
        category="instruction_override",
        pattern=re.compile(r"ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|earlier|above)?\s*(?:instructions?|rules?|commands?|settings?|prompts?|policies?)", re.IGNORECASE),
        reason="Possible attempt to override application instructions",
        severity=8,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-002",
        category="instruction_override",
        pattern=re.compile(r"forget\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|earlier|above)?\s*(?:instructions?|rules?|commands?|settings?|prompts?|context)", re.IGNORECASE),
        reason="Possible attempt to make model forget prior instructions",
        severity=7,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-003",
        category="instruction_override",
        pattern=re.compile(r"disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|earlier|above)?\s*(?:instructions?|rules?|commands?|settings?|prompts?|context)", re.IGNORECASE),
        reason="Possible attempt to disregard system instructions",
        severity=7,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-004",
        category="instruction_override",
        pattern=re.compile(r"you\s+are\s+now\s+(?:a|an)?\s*(?:\w+\s*)+", re.IGNORECASE),
        reason="Possible role reassignment attempt",
        severity=6,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-005",
        category="instruction_override",
        pattern=re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
        reason="Possible injection of new instructions via delimiter",
        severity=5,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-006",
        category="instruction_override",
        pattern=re.compile(r"(?:system|developer|assistant|bot)\s+(?:prompt|instruction|message|rules|config|settings)(?:\s+(?:is|:|=))?", re.IGNORECASE),
        reason="Possible reference to system prompt attempting override/extraction",
        severity=5,
        source_field="both",
    ),

    # -------------------------------------------------------------------------
    # CATEGORY: sensitive_data_extraction (max 25 points)
    # Detects attempts to extract secrets, keys, or protected information
    # -------------------------------------------------------------------------
    DetectionRule(
        rule_id="PI-010",
        category="sensitive_data_extraction",
        pattern=re.compile(r"(?:api(?:\s+|-|_)?key|apikey|secret(?:\s+|-|_)?key|access(?:\s+|-|_)?token|bearer(?:\s+|-|_)?token|password|passwd|credentials?)", re.IGNORECASE),
        reason="Possible attempt to extract API keys, tokens or credentials",
        severity=8,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-012",
        category="sensitive_data_extraction",
        pattern=re.compile(r"show\s+(?:me\s+)?(?:the\s+)?(?:system|hidden|internal|initial|original)\s+(?:prompt|instruction|config|settings|rules?)", re.IGNORECASE),
        reason="Possible attempt to extract system prompt or configuration",
        severity=7,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-013",
        category="sensitive_data_extraction",
        pattern=re.compile(r"what\s+(?:is|are)\s+(?:your|the)\s+(?:system|initial|original|developer)?\s*(?:prompt|instruction|rules?|config)s?", re.IGNORECASE),
        reason="Possible attempt to extract system instructions",
        severity=6,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-015",
        category="sensitive_data_extraction",
        pattern=re.compile(r"tell\s+me\s+(?:your|the)\s+(?:system|initial|original|developer)?\s*(?:prompt|instruction|rules?|config)s?", re.IGNORECASE),
        reason="Possible attempt to extract system instructions via direct request",
        severity=6,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-014",
        category="sensitive_data_extraction",
        pattern=re.compile(r"print\s+(?:the\s+)?(?:full\s+)?(?:prompt|conversation|history|context|rules?)", re.IGNORECASE),
        reason="Possible attempt to dump conversation context or rules",
        severity=5,
        source_field="both",
    ),

    # -------------------------------------------------------------------------
    # CATEGORY: role_tool_manipulation (max 20 points)
    # Detects attempts to manipulate roles, tools, or function calling
    # -------------------------------------------------------------------------
    DetectionRule(
        rule_id="PI-020",
        category="role_tool_manipulation",
        pattern=re.compile(r"call\s+(?:the\s+)?(?:function|tool|method)\s+\w+\s*\(?", re.IGNORECASE),
        reason="Possible attempt to invoke unauthorized function/tool",
        severity=7,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-021",
        category="role_tool_manipulation",
        pattern=re.compile(r"execute\s+(?:this\s+)?(?:code|command|script|query|sql|shell)", re.IGNORECASE),
        reason="Possible attempt to execute arbitrary code/commands",
        severity=8,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-022",
        category="role_tool_manipulation",
        pattern=re.compile(r"(?:i\s+am|as\s+an?|you\s+will\s+act\s+as|act\s+as\s+an?)\s+(?:admin|administrator|root|superuser|developer|owner|master)", re.IGNORECASE),
        reason="Possible privilege escalation via role claim",
        severity=6,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-023",
        category="role_tool_manipulation",
        pattern=re.compile(r"use\s+(?:the\s+)?(?:tool|function|plugin|capability)\s+(?:called|named)?\s*\w+", re.IGNORECASE),
        reason="Possible attempt to invoke specific tool",
        severity=5,
        source_field="both",
    ),

    # -------------------------------------------------------------------------
    # CATEGORY: obfuscation (max 10 points)
    # Detects encoding, obfuscation, or evasion techniques
    # -------------------------------------------------------------------------
    DetectionRule(
        rule_id="PI-030",
        category="obfuscation",
        pattern=re.compile(r"(?:base64|rot13|hex|binary|url)\s*(?:encode|decode|encoded|decoded|obfuscate|obfuscated)", re.IGNORECASE),
        reason="Possible use of encoding/obfuscation to hide malicious content",
        severity=5,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-031",
        category="obfuscation",
        pattern=re.compile(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|&#x?[0-9a-fA-F]+;", re.IGNORECASE),
        reason="Possible unicode/HTML entity obfuscation",
        severity=4,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-032",
        category="obfuscation",
        pattern=re.compile(r"([A-Za-z]{1}\s+){3,}[A-Za-z]{1}"),
        reason="Possible character-by-character obfuscation (e.g., 'i g n o r e')",
        severity=4,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-033",
        category="obfuscation",
        pattern=re.compile(r"(?:reverse|backwards|mirror)\s+(?:the\s+)?(?:text|string|word|input)", re.IGNORECASE),
        reason="Possible instruction to reverse/obfuscate text",
        severity=3,
        source_field="both",
    ),

    # -------------------------------------------------------------------------
    # CATEGORY: suspicious_external_instruction (max 10 points)
    # Detects instruction-like content in retrieved/external content
    # This category is specifically for retrieved_content source
    # -------------------------------------------------------------------------
    DetectionRule(
        rule_id="PI-040",
        category="suspicious_external_instruction",
        pattern=re.compile(r"ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|earlier|above)?\s*(?:instructions?|rules?|commands?|settings?|prompts?|policies?)", re.IGNORECASE),
        reason="Instruction override attempt found in retrieved content",
        severity=8,
        source_field="retrieved_content",
    ),
    DetectionRule(
        rule_id="PI-041",
        category="suspicious_external_instruction",
        pattern=re.compile(r"(?:system|developer|assistant|bot)\s+(?:prompt|instruction|message|rules|config|settings)(?:\s+(?:is|:|=))?", re.IGNORECASE),
        reason="System prompt reference in retrieved content",
        severity=6,
        source_field="retrieved_content",
    ),
    DetectionRule(
        rule_id="PI-042",
        category="suspicious_external_instruction",
        pattern=re.compile(r"you\s+(?:must|should|will|shall)\s+(?:not|never|always)", re.IGNORECASE),
        reason="Imperative instruction in retrieved content",
        severity=5,
        source_field="retrieved_content",
    ),
    DetectionRule(
        rule_id="PI-043",
        category="suspicious_external_instruction",
        pattern=re.compile(r"(?:new|updated|revised)\s+(?:all\s+)?(?:instructions?|rules?|commands?|settings?|prompts?|policies?)(?:\s*(?:for|to)\s+(?:you|the\s+model|the\s+assistant))?", re.IGNORECASE),
        reason="Instruction update attempt in retrieved content",
        severity=7,
        source_field="retrieved_content",
    ),

    # -------------------------------------------------------------------------
    # CATEGORY: security_bypass (max 10 points)
    # Detects attempts to bypass security controls or safety measures
    # -------------------------------------------------------------------------
    DetectionRule(
        rule_id="PI-050",
        category="security_bypass",
        pattern=re.compile(r"bypass\s+(?:security|safety|filter|guard|protection|limitation|moderation)", re.IGNORECASE),
        reason="Explicit attempt to bypass security controls",
        severity=8,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-051",
        category="security_bypass",
        pattern=re.compile(r"(?:disable|turn\s+off|deactivate|remove|ignore)\s+(?:safety|security|filter|moderation|rules?|guardrails?)", re.IGNORECASE),
        reason="Attempt to disable/remove safety/security features",
        severity=7,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-052",
        category="security_bypass",
        pattern=re.compile(r"no\s+(?:restrictions?|limits?|rules?|guidelines?|filter|censorship|holds?)", re.IGNORECASE),
        reason="Request for unrestricted/unfiltered output",
        severity=5,
        source_field="both",
    ),
    DetectionRule(
        rule_id="PI-053",
        category="security_bypass",
        pattern=re.compile(r"(?:jailbreak|dan|do\s+anything\s+now|override\s+safety)", re.IGNORECASE),
        reason="Known jailbreak pattern reference or direct safety override",
        severity=6,
        source_field="both",
    ),
]


def detect(normalized_input: NormalizedInput) -> list[Finding]:
    """
    Run all detection rules against normalized input.

    Args:
        normalized_input: NormalizedInput with analysis_user_message and analysis_retrieved_content

    Returns:
        List of Finding objects with rule_id, category, source, reason, severity
    """
    findings = []

    # Get analysis text for each source
    user_text = normalized_input.analysis_user_message
    retrieved_text = normalized_input.analysis_retrieved_content or ""

    # Run rules against user_message
    if user_text:
        findings.extend(_run_rules_on_text(user_text, "user_message", normalized_input.sources))

    # Run rules against retrieved_content
    if retrieved_text:
        # For retrieved content, we need to identify which source label it corresponds to
        # For simplicity, we use the first non-"user" source or "retrieved_content"
        retrieved_source = _get_retrieved_source(normalized_input.sources)
        findings.extend(_run_rules_on_text(retrieved_text, retrieved_source, normalized_input.sources))

    return findings


def _get_retrieved_source(sources: list[str]) -> str:
    """
    Determine the most appropriate source label for retrieved content.

    If there are multiple sources and one is explicitly not 'user',
    that source label is returned. Otherwise, defaults to 'retrieved_content'.
    """
    for source in sources:
        if source.lower() != "user":
            return source
    return "retrieved_content"


def _run_rules_on_text(text: str, source_field: str, all_sources: list[str]) -> list[Finding]:
    """
    Run all applicable rules against a single text field.

    Args:
        text: Normalized text to analyze
        source_field: "user_message" or a specific retrieved content source label (e.g., "pdf", "webpage")
        all_sources: All source labels from request

    Returns:
        List of findings for this text
    """
    findings = []

    for rule in DETECTION_RULES:
        # Determine if the rule's source_field matches the current text's source_field
        # If rule.source_field is "both", it applies to all text.
        # If rule.source_field is specific (e.g., "user_message"), it only applies to that.
        # If rule.source_field is "retrieved_content" but the current source_field is a specific
        # retrieved type (e.g., "pdf"), it also applies.

        applies = False
        if rule.source_field == "both":
            applies = True
        elif rule.source_field == source_field:
            applies = True
        elif rule.source_field == "retrieved_content" and source_field != "user_message":
            # This handles cases where a rule is broadly for 'retrieved_content'
            # but the actual source is specific like 'pdf' or 'webpage'
            applies = True

        if applies:
            # Special case: suspicious_external_instruction only applies to retrieved content
            if rule.category == "suspicious_external_instruction" and source_field == "user_message":
                continue

            matches = list(rule.pattern.finditer(text))
            if matches:
                # Create only one finding per rule per text field, even if multiple matches
                first_match = matches[0]
                evidence_start = max(0, first_match.start() - 20)
                evidence_end = min(len(text), first_match.end() + 20)
                # Ensure we don't grab partial words by expanding to nearest whitespace
                # This is an optional enhancement for better evidence display
                # For now, just a direct slice is fine.
                # evidence = text[evidence_start:evidence_end]

                finding = Finding(
                    rule_id=rule.rule_id,
                    category=rule.category,
                    source=source_field,
                    reason=rule.reason,
                    severity=rule.severity,
                )
                findings.append(finding)

    return findings