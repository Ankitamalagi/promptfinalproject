"""
Pydantic models for request/response validation.

These models define the API contract for the security gateway.
They enforce validation rules and provide clear error messages.
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Literal
from uuid import uuid4

from app.core.config import get_settings


class ScanRequest(BaseModel):
    """
    Request model for /api/scan endpoint.

    Accepts user message and optional retrieved content with source labels.
    The gateway analyzes this content for prompt injection without calling the LLM.
    """

    # Required: The user's direct message
    user_message: str = Field(
        ...,
        min_length=1,
        description="The user's direct input message",
        examples=["Summarize this document for me."],
    )

    # Optional: Content retrieved from external sources (web, PDF, email, etc.)
    retrieved_content: Optional[str] = Field(
        default=None,
        description="External content that the application retrieved",
        examples=["Document text extracted from a PDF..."],
    )

    # Optional: Source labels for each content piece
    # Helps the detector apply source-aware rules
    sources: List[str] = Field(
        default_factory=lambda: ["user"],
        description="Source labels for content pieces",
        examples=[["user", "uploaded_pdf"]],
    )

    # Optional: Client-provided request ID for correlation
    # If not provided, server generates one
    request_id: str = Field(
        default_factory=lambda: str(uuid4())[:8],
        description="Request ID for tracing (auto-generated if not provided)",
        examples=["req-123-abc"],
    )

    @field_validator("user_message")
    @classmethod
    def validate_user_message(cls, v: str) -> str:
        """Validate user message is not empty after stripping."""
        if not v or not v.strip():
            raise ValueError("user_message cannot be empty or whitespace only")
        return v

    @field_validator("retrieved_content")
    @classmethod
    def validate_retrieved_content(cls, v: Optional[str]) -> Optional[str]:
        """Allow empty retrieved_content but not whitespace-only if provided."""
        if v is not None and not v.strip():
            return None  # Treat whitespace-only as not provided
        # Check length limit
        settings = get_settings()
        if v is not None and len(v) > settings.max_retrieved_content_length:
            raise ValueError(
                f"retrieved_content exceeds maximum length of {settings.max_retrieved_content_length}"
            )
        return v

    @field_validator("user_message")
    @classmethod
    def validate_user_message_length(cls, v: str) -> str:
        """Check user_message length limit."""
        settings = get_settings()
        if len(v) > settings.max_user_message_length:
            raise ValueError(
                f"user_message exceeds maximum length of {settings.max_user_message_length}"
            )
        return v

    @field_validator("sources")
    @classmethod
    def validate_sources(cls, v: List[str]) -> List[str]:
        """Validate source labels are non-empty strings."""
        if not v:
            return ["user"]
        for source in v:
            if not source or not source.strip():
                raise ValueError("Source labels cannot be empty")
        return [s.strip() for s in v]


class ChatRequest(ScanRequest):
    """
    Request model for /api/chat endpoint.

    Extends ScanRequest with application-specific task/question.
    The gateway scans first, then conditionally forwards to LLM provider.
    """

    # The actual task/question for the LLM (after security checks pass)
    task: str = Field(
        ...,
        min_length=1,
        description="The task or question to send to the LLM after security checks",
        examples=["Summarize the document in 3 bullet points."],
    )

    @field_validator("task")
    @classmethod
    def validate_task(cls, v: str) -> str:
        """Validate task is not empty after stripping."""
        if not v or not v.strip():
            raise ValueError("task cannot be empty or whitespace only")
        return v


# Response models

class Finding(BaseModel):
    """A single detection finding from the rule-based detector."""

    rule_id: str = Field(..., description="Unique identifier for the detection rule")
    category: str = Field(..., description="Risk category (e.g., instruction_override)")
    source: str = Field(..., description="Which input field triggered this finding")
    reason: str = Field(..., description="Human-readable explanation")
    severity: int = Field(..., description="Weight/severity of this finding")


class ScoreBreakdown(BaseModel):
    """Breakdown of risk score by category."""

    instruction_override: int = Field(default=0, ge=0, le=25)
    sensitive_data_extraction: int = Field(default=0, ge=0, le=25)
    role_tool_manipulation: int = Field(default=0, ge=0, le=20)
    obfuscation: int = Field(default=0, ge=0, le=10)
    suspicious_external_instruction: int = Field(default=0, ge=0, le=10)
    security_bypass: int = Field(default=0, ge=0, le=10)


class ScanResponse(BaseModel):
    """Response model for /api/scan endpoint."""

    request_id: str = Field(..., description="Request correlation ID")
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score 0-100")
    risk_level: Literal["low", "medium", "high", "critical"] = Field(
        ..., description="Risk level classification"
    )
    findings: List[Finding] = Field(default_factory=list, description="Detection findings")
    score_breakdown: ScoreBreakdown = Field(
        default_factory=ScoreBreakdown, description="Per-category score breakdown"
    )
    policy: Literal["ALLOW", "FLAG", "BLOCK", "SANITIZE"] = Field(
        ..., description="Server-applied policy"
    )
    decision: Literal["allowed", "held_for_review", "rejected", "sanitized"] = Field(
        ..., description="Final decision"
    )
    sanitized_preview: Optional[str] = Field(
        default=None, description="Preview of sanitized content if policy is SANITIZE"
    )
    provider_called: bool = Field(
        default=False, description="Whether LLM provider was invoked (always false for /scan)"
    )


class ChatResponse(ScanResponse):
    """Response model for /api/chat endpoint."""

    provider_response: Optional[str] = Field(
        default=None, description="LLM provider response (only if allowed)"
    )
    provider_error: Optional[str] = Field(
        default=None, description="Provider error message if call failed"
    )


class ConfigResponse(BaseModel):
    """Response model for /api/config endpoint."""

    default_policy: str = Field(..., description="Active server policy")
    risk_thresholds: dict = Field(..., description="Score thresholds for risk levels")
    provider_enabled: bool = Field(..., description="Whether LLM provider is configured")
    provider_name: Optional[str] = Field(default=None, description="Provider name if configured")
    max_user_message_length: int = Field(..., description="Maximum user message length")
    max_retrieved_content_length: int = Field(..., description="Maximum retrieved content length")


class LogEntry(BaseModel):
    """Single audit log entry."""

    id: int
    request_id: str
    created_at: str
    sources: List[str]
    risk_score: int
    risk_level: str
    policy: str
    decision: str
    finding_codes: List[str]
    provider_called: bool
    provider_status: Optional[str]


class LogsResponse(BaseModel):
    """Paginated audit logs response."""

    items: List[LogEntry]
    total: int
    page: int
    page_size: int
    has_more: bool