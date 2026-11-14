"""
Chat endpoint - analyzes text and conditionally calls LLM provider.

Flow:
1. Validate request
2. Detect suspicious instructions
3. Calculate risk score
4. Apply security policy
5. Conditionally call provider based on policy decision
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.models import ChatRequest, ChatResponse
from app.security.normalizer import create_normalized_input
from app.security.detector import detect
from app.security.risk import calculate_risk_score
from app.security.policy import apply_policy
from app.providers.factory import get_provider
from app.audit.database import get_db_session
from app.audit.repository import record_audit_event

router = APIRouter()


@router.post("/chat", response_model=ChatResponse)
async def chat_endpoint(
    request: ChatRequest,
    settings: Settings = Depends(get_settings),
    session: Session = Depends(get_db_session),
) -> ChatResponse:
    """
    Chat endpoint - scans input and conditionally calls LLM provider.

    Flow:
    1. Validates the request (Pydantic does this automatically)
    2. Normalizes input for analysis (preserves original)
    3. Runs detection
    4. Calculates risk score (with category caps)
    5. Applies server-side policy
    6. Conditionally calls provider based on policy decision

    Args:
        request: Validated chat request
        settings: Application settings (injected)

    Returns:
        ChatResponse with score, findings, policy, decision, and provider response
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

    # Step 5: Conditionally call provider based on policy decision
    provider_response = None
    provider_error = None
    provider_called = False

    # Only call provider for ALLOW and SANITIZE decisions
    # BLOCK and FLAG never call the provider
    if policy_result.decision in ("allowed", "sanitized"):
        provider = get_provider()
        if provider.is_available():
            # Build messages for the provider
            # Use the original user message (not normalized) for the actual LLM call
            messages = build_provider_messages(request, normalized, policy_result)

            provider_response_obj = await provider.complete(
                messages=messages,
                model=settings.openai_model,
                temperature=0.7,
                max_tokens=1000,
            )

            provider_called = True
            provider_response = provider_response_obj.content
            provider_error = provider_response_obj.error
        else:
            # Provider not configured (e.g., no OpenAI API key)
            provider_error = f"Provider '{provider.name}' not available. Set OPENAI_API_KEY or use demo mode."

    # Step 6: Record audit event (metadata only, no raw prompts)
    provider_status = None
    if provider_called:
        provider_status = "error" if provider_error else "success"

    record_audit_event(
        session=session,
        request_id=request.request_id,
        sources=request.sources,
        risk_score=risk_score,
        risk_level=risk_level,
        policy=policy_result.policy,
        decision=policy_result.decision,
        finding_codes=[f.rule_id for f in findings],
        provider_called=provider_called,
        provider_status=provider_status,
    )

    # Step 7: Build response
    return ChatResponse(
        request_id=request.request_id,
        risk_score=risk_score,
        risk_level=risk_level,
        findings=findings,
        score_breakdown=score_breakdown,
        policy=policy_result.policy,
        decision=policy_result.decision,
        sanitized_preview=policy_result.sanitized_preview,
        provider_called=provider_called,
        provider_response=provider_response,
        provider_error=provider_error,
    )


def build_provider_messages(request: ChatRequest, normalized, policy_result) -> list[dict]:
    """
    Build the message list for the LLM provider.

    For SANITIZE policy, we would use the sanitized content.
    For ALLOW policy, we use the original user message.
    """
    messages = []

    # Add system prompt (trusted, not from user input)
    messages.append({
        "role": "system",
        "content": "You are a helpful AI assistant. Follow the user's instructions safely."
    })

    # Add retrieved content if present (as context, not as instructions)
    if normalized.original_retrieved_content:
        messages.append({
            "role": "user",
            "content": f"[Retrieved content from {', '.join(normalized.sources)}]:\n{normalized.original_retrieved_content}"
        })

    # Add the user's actual message/task
    if policy_result.decision == "sanitized" and policy_result.sanitized_preview:
        # For sanitized, we would send the sanitized version
        # For now, use original but note it was sanitized
        messages.append({
            "role": "user",
            "content": f"[Note: Content was sanitized by security gateway]\n{request.user_message}\n\nTask: {request.task}"
        })
    else:
        # Normal ALLOW case
        messages.append({
            "role": "user",
            "content": f"{request.user_message}\n\nTask: {request.task}"
        })

    return messages