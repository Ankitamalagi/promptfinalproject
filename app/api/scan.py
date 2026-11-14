"""
Scan endpoint - analyzes text for prompt injection without calling provider.

Accepts user_message, optional retrieved_content, sources, and request_id.
Returns risk score, findings, policy decision (but never calls provider).
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.models import ScanRequest, ScanResponse
from app.security.normalizer import create_normalized_input
from app.security.detector import detect
from app.security.risk import calculate_risk_score
from app.security.policy import apply_policy
from app.audit.database import get_db_session
from app.audit.repository import record_audit_event

router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
async def scan_endpoint(
    request: ScanRequest,
    settings: Settings = Depends(get_settings),
    session: Session = Depends(get_db_session),
) -> ScanResponse:
    """
    Scan endpoint - analyzes input for prompt injection indicators.

    This endpoint:
    1. Validates the request (Pydantic does this automatically)
    2. Normalizes input for analysis (preserves original)
    3. Runs detection
    4. Calculates risk score (with category caps)
    5. Applies server-side policy
    6. Returns decision (never calls provider)

    Args:
        request: Validated scan request
        settings: Application settings (injected)

    Returns:
        ScanResponse with score, findings, policy, and decision
    """
    # Step 1: Create normalized input (preserves originals)
    normalized = create_normalized_input(
        user_message=request.user_message,
        retrieved_content=request.retrieved_content,
        sources=request.sources,
    )

    # Step 2: Run detection
    findings = detect(normalized)

    # Step 3: Calculate risk score using dedicated module
    risk_result = calculate_risk_score(findings)
    risk_score = risk_result.total_score
    risk_level = risk_result.risk_level
    score_breakdown = risk_result.score_breakdown

    # Step 4: Apply server-side policy using policy engine
    policy_result = apply_policy(
        policy=settings.default_policy,
        risk_score=risk_score,
        findings=findings,
        settings=settings,
    )

    # Step 5: Record audit event (metadata only, no raw prompts)
    record_audit_event(
        session=session,
        request_id=request.request_id,
        sources=request.sources,
        risk_score=risk_score,
        risk_level=risk_level,
        policy=policy_result.policy,
        decision=policy_result.decision,
        finding_codes=[f.rule_id for f in findings],
        provider_called=policy_result.provider_called,
        provider_status=None,
    )

    # Step 6: Build response
    return ScanResponse(
        request_id=request.request_id,
        risk_score=risk_score,
        risk_level=risk_level,
        findings=findings,
        score_breakdown=score_breakdown,
        policy=policy_result.policy,
        decision=policy_result.decision,
        sanitized_preview=policy_result.sanitized_preview,
        provider_called=policy_result.provider_called,
    )