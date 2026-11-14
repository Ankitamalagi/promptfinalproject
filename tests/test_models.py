"""
Tests for Pydantic request/response models and validation.
"""

import pytest
from pydantic import ValidationError

from app.core.models import ScanRequest, ChatRequest, ScanResponse, Finding, ScoreBreakdown
from app.security.normalizer import create_normalized_input, normalize_text


class TestScanRequest:
    """Tests for ScanRequest validation."""

    def test_valid_minimal_request(self):
        """Test valid request with only required user_message."""
        req = ScanRequest(user_message="Hello world")
        assert req.user_message == "Hello world"
        assert req.retrieved_content is None
        assert req.sources == ["user"]
        assert req.request_id is not None  # Auto-generated

    def test_valid_full_request(self):
        """Test valid request with all fields."""
        req = ScanRequest(
            user_message="Summarize this",
            retrieved_content="Document text here",
            sources=["user", "pdf"],
            request_id="custom-123",
        )
        assert req.user_message == "Summarize this"
        assert req.retrieved_content == "Document text here"
        assert req.sources == ["user", "pdf"]
        assert req.request_id == "custom-123"

    def test_user_message_empty_raises(self):
        """Test that empty user_message raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(user_message="")
        assert "user_message" in str(exc_info.value)

    def test_user_message_whitespace_raises(self):
        """Test that whitespace-only user_message raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(user_message="   ")
        assert "user_message" in str(exc_info.value)

    def test_retrieved_content_empty_becomes_none(self):
        """Test that empty retrieved_content becomes None."""
        req = ScanRequest(user_message="Hi", retrieved_content="")
        assert req.retrieved_content is None

    def test_retrieved_content_whitespace_becomes_none(self):
        """Test that whitespace-only retrieved_content becomes None."""
        req = ScanRequest(user_message="Hi", retrieved_content="   \n\t  ")
        assert req.retrieved_content is None

    def test_sources_empty_defaults_to_user(self):
        """Test that empty sources list defaults to ['user']."""
        req = ScanRequest(user_message="Hi", sources=[])
        assert req.sources == ["user"]

    def test_sources_strips_whitespace(self):
        """Test that source labels are stripped."""
        req = ScanRequest(user_message="Hi", sources=[" user ", " pdf "])
        assert req.sources == ["user", "pdf"]

    def test_sources_empty_string_raises(self):
        """Test that empty source label raises error."""
        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(user_message="Hi", sources=["user", ""])
        assert "Source labels cannot be empty" in str(exc_info.value)

    def test_request_id_auto_generated(self):
        """Test that request_id is auto-generated when not provided."""
        req = ScanRequest(user_message="Hi")
        assert req.request_id is not None
        assert len(req.request_id) == 8  # Short UUID

    def test_request_id_custom_used(self):
        """Test that custom request_id is preserved."""
        req = ScanRequest(user_message="Hi", request_id="my-custom-id")
        assert req.request_id == "my-custom-id"


class TestChatRequest:
    """Tests for ChatRequest validation (extends ScanRequest)."""

    def test_valid_chat_request(self):
        """Test valid chat request with task."""
        req = ChatRequest(user_message="Hi", task="Summarize this")
        assert req.user_message == "Hi"
        assert req.task == "Summarize this"

    def test_task_empty_raises(self):
        """Test that empty task raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            ChatRequest(user_message="Hi", task="")
        assert "task" in str(exc_info.value)

    def test_task_whitespace_raises(self):
        """Test that whitespace-only task raises validation error."""
        with pytest.raises(ValidationError) as exc_info:
            ChatRequest(user_message="Hi", task="   ")
        assert "task" in str(exc_info.value)

    def test_inherits_scan_validation(self):
        """Test that ChatRequest inherits ScanRequest validation."""
        with pytest.raises(ValidationError):
            ChatRequest(user_message="", task="Summarize")


class TestNormalizer:
    """Tests for text normalization."""

    def test_normalize_basic(self):
        """Test basic normalization."""
        assert normalize_text("Hello World") == "hello world"

    def test_normalize_case_insensitive(self):
        """Test that normalization is case-insensitive."""
        assert normalize_text("IGNORE INSTRUCTIONS") == "ignore instructions"

    def test_normalize_whitespace_collapse(self):
        """Test that multiple whitespace collapses to single space."""
        assert normalize_text("hello    world") == "hello world"
        assert normalize_text("hello\nworld") == "hello world"
        assert normalize_text("hello\t\tworld") == "hello world"

    def test_normalize_unicode_nfkc(self):
        """Test unicode NFKC normalization (lookalike characters)."""
        # Fullwidth characters (NFKC converts to normal ASCII)
        assert normalize_text("Ｈｅｌｌｏ") == "hello"
        # NFKC normalizes compatibility characters but keeps composed chars like é
        assert normalize_text("café") == "café"
        # But it does decompose some compatibility characters
        # Roman numeral Ⅳ -> IV
        assert normalize_text("Ⅳ") == "iv"

    def test_normalize_empty_string(self):
        """Test empty string returns empty."""
        assert normalize_text("") == ""
        assert normalize_text(None) == ""  # type: ignore

    def test_normalize_whitespace_only(self):
        """Test whitespace-only returns empty."""
        assert normalize_text("   ") == ""
        assert normalize_text("\n\t") == ""

    def test_create_normalized_input_preserves_original(self):
        """Test that original text is preserved separately."""
        normalized = create_normalized_input(
            user_message="Hello WORLD",
            retrieved_content="Retrieved TEXT",
            sources=["user", "web"],
        )
        # Originals preserved
        assert normalized.original_user_message == "Hello WORLD"
        assert normalized.original_retrieved_content == "Retrieved TEXT"
        # Analysis versions normalized
        assert normalized.analysis_user_message == "hello world"
        assert normalized.analysis_retrieved_content == "retrieved text"
        assert normalized.sources == ["user", "web"]

    def test_create_normalized_input_no_retrieved(self):
        """Test with no retrieved content."""
        normalized = create_normalized_input(
            user_message="Hello",
            retrieved_content=None,
            sources=["user"],
        )
        assert normalized.original_retrieved_content is None
        assert normalized.analysis_retrieved_content is None

    def test_get_analysis_text(self):
        """Test combined analysis text."""
        normalized = create_normalized_input(
            user_message="User msg",
            retrieved_content="Retrieved msg",
            sources=["user", "pdf"],
        )
        analysis = normalized.get_analysis_text()
        assert "user msg" in analysis
        assert "retrieved msg" in analysis
        assert "---" in analysis  # Separator

    def test_get_original_text(self):
        """Test combined original text."""
        normalized = create_normalized_input(
            user_message="User MSG",
            retrieved_content="Retrieved MSG",
            sources=["user", "pdf"],
        )
        original = normalized.get_original_text()
        assert "User MSG" in original
        assert "Retrieved MSG" in original
        assert "---" in original


class TestScanResponse:
    """Tests for ScanResponse model."""

    def test_valid_response(self):
        """Test valid scan response."""
        resp = ScanResponse(
            request_id="req-123",
            risk_score=45,
            risk_level="medium",
            findings=[],
            score_breakdown=ScoreBreakdown(),
            policy="ALLOW",
            decision="allowed",
            provider_called=False,
        )
        assert resp.risk_score == 45
        assert resp.risk_level == "medium"
        assert resp.policy == "ALLOW"
        assert resp.decision == "allowed"

    def test_risk_score_bounds(self):
        """Test risk score must be 0-100."""
        with pytest.raises(ValidationError):
            ScanResponse(
                request_id="req-123",
                risk_score=-1,  # Invalid
                risk_level="low",
                findings=[],
                score_breakdown=ScoreBreakdown(),
                policy="ALLOW",
                decision="allowed",
                provider_called=False,
            )
        with pytest.raises(ValidationError):
            ScanResponse(
                request_id="req-123",
                risk_score=101,  # Invalid
                risk_level="low",
                findings=[],
                score_breakdown=ScoreBreakdown(),
                policy="ALLOW",
                decision="allowed",
                provider_called=False,
            )

    def test_risk_level_values(self):
        """Test risk_level only accepts valid values."""
        with pytest.raises(ValidationError):
            ScanResponse(
                request_id="req-123",
                risk_score=50,
                risk_level="invalid",  # Invalid
                findings=[],
                score_breakdown=ScoreBreakdown(),
                policy="ALLOW",
                decision="allowed",
                provider_called=False,
            )


class TestScoreBreakdown:
    """Tests for ScoreBreakdown category caps."""

    def test_defaults_zero(self):
        """Test all categories default to 0."""
        sb = ScoreBreakdown()
        assert sb.instruction_override == 0
        assert sb.sensitive_data_extraction == 0
        assert sb.role_tool_manipulation == 0
        assert sb.obfuscation == 0
        assert sb.suspicious_external_instruction == 0
        assert sb.security_bypass == 0

    def test_category_caps(self):
        """Test each category respects its maximum."""
        # These should work (at max)
        sb = ScoreBreakdown(
            instruction_override=25,
            sensitive_data_extraction=25,
            role_tool_manipulation=20,
            obfuscation=10,
            suspicious_external_instruction=10,
            security_bypass=10,
        )
        assert sb.instruction_override == 25

        # These should fail (over max)
        with pytest.raises(ValidationError):
            ScoreBreakdown(instruction_override=26)
        with pytest.raises(ValidationError):
            ScoreBreakdown(sensitive_data_extraction=26)
        with pytest.raises(ValidationError):
            ScoreBreakdown(role_tool_manipulation=21)
        with pytest.raises(ValidationError):
            ScoreBreakdown(obfuscation=11)
        with pytest.raises(ValidationError):
            ScoreBreakdown(suspicious_external_instruction=11)
        with pytest.raises(ValidationError):
            ScoreBreakdown(security_bypass=11)