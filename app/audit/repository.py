"""
Audit Repository

Handles persistence and retrieval of security audit events.
"""

from typing import Optional, List, Tuple
from sqlalchemy import select, func, desc
from sqlalchemy.orm import Session

from app.audit.database import AuditEvent


def record_audit_event(
    session: Session,
    request_id: str,
    sources: list[str],
    risk_score: int,
    risk_level: str,
    policy: str,
    decision: str,
    finding_codes: list[str],
    provider_called: bool,
    provider_status: Optional[str] = None,
) -> AuditEvent:
    """
    Persist a minimal security event record to the audit database.

    Notice that raw prompts and sensitive keys are NEVER passed or stored.
    """
    event = AuditEvent(
        request_id=request_id,
        sources=sources,
        risk_score=risk_score,
        risk_level=risk_level,
        policy=policy,
        decision=decision,
        finding_codes=finding_codes,
        provider_called=provider_called,
        provider_status=provider_status,
    )
    session.add(event)
    session.commit()
    session.refresh(event)
    return event


def get_audit_events(
    session: Session,
    page: int = 1,
    page_size: int = 20,
) -> Tuple[List[AuditEvent], int]:
    """
    Retrieve paginated audit events ordered newest first.

    Args:
        session: Active database session
        page: Page number (1-indexed)
        page_size: Number of items per page (bounded between 1 and 100)

    Returns:
        Tuple of (list of audit event records, total count)
    """
    page = max(1, page)
    page_size = max(1, min(100, page_size))
    offset = (page - 1) * page_size

    total_query = select(func.count(AuditEvent.id))
    total = session.execute(total_query).scalar() or 0

    items_query = (
        select(AuditEvent)
        .order_by(desc(AuditEvent.id))
        .offset(offset)
        .limit(page_size)
    )
    items = list(session.execute(items_query).scalars().all())

    return items, total


def get_audit_stats(session: Session) -> dict:
    """
    Get aggregated audit statistics for dashboard reporting.
    """
    total_query = select(func.count(AuditEvent.id))
    total = session.execute(total_query).scalar() or 0

    decisions_query = select(AuditEvent.decision, func.count(AuditEvent.id)).group_by(AuditEvent.decision)
    decisions_res = session.execute(decisions_query).all()
    decisions_map = dict(decisions_res)

    provider_called_query = select(func.count(AuditEvent.id)).where(AuditEvent.provider_called.is_(True))
    provider_called_count = session.execute(provider_called_query).scalar() or 0

    return {
        "total_requests": total,
        "decisions": {
            "allowed": decisions_map.get("allowed", 0),
            "held_for_review": decisions_map.get("held_for_review", 0),
            "rejected": decisions_map.get("rejected", 0),
            "sanitized": decisions_map.get("sanitized", 0),
        },
        "provider_called_count": provider_called_count,
    }
