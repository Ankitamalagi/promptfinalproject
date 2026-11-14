"""
Logs endpoint - paginated audit metadata.

Exposes security audit events without raw prompt content or credentials.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.models import LogsResponse, LogEntry
from app.audit.database import get_db_session
from app.audit.repository import get_audit_events, get_audit_stats

router = APIRouter()


@router.get("/logs", response_model=LogsResponse)
async def logs_endpoint(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Page size (max 100)"),
    session: Session = Depends(get_db_session),
) -> LogsResponse:
    """
    Return paginated audit events ordered newest first.

    Guarantees:
    - Bounded page sizes (1 to 100)
    - Privacy-conscious (contains metadata, risk score, findings, but no raw prompt content)
    """
    events, total = get_audit_events(session=session, page=page, page_size=page_size)

    items = [
        LogEntry(
            id=event.id,
            request_id=event.request_id,
            created_at=event.created_at.isoformat() if event.created_at else "",
            sources=event.sources or [],
            risk_score=event.risk_score,
            risk_level=event.risk_level,
            policy=event.policy,
            decision=event.decision,
            finding_codes=event.finding_codes or [],
            provider_called=event.provider_called,
            provider_status=event.provider_status,
        )
        for event in events
    ]

    has_more = (page * page_size) < total

    return LogsResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        has_more=has_more,
    )


@router.get("/logs/stats")
async def logs_stats_endpoint(
    session: Session = Depends(get_db_session),
):
    """
    Return aggregate statistics for audit dashboard.
    """
    return get_audit_stats(session=session)
