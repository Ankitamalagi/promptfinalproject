"""
Audit Database Module

Sets up SQLite database using SQLAlchemy.
Stores security audit metadata without storing raw prompt content.
"""

from datetime import datetime, timezone
from typing import Optional, Generator
from sqlalchemy import Integer, String, Boolean, DateTime, JSON, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


class AuditEvent(Base):
    """
    SQLAlchemy model for recorded security events.

    Security/Privacy Note:
    Raw prompt text and secrets are intentionally excluded from this table
    to avoid storing sensitive user data. Only metadata is preserved.
    """
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    sources: Mapped[list] = mapped_column(JSON, default=list)
    risk_score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[str] = mapped_column(String(16))
    policy: Mapped[str] = mapped_column(String(16))
    decision: Mapped[str] = mapped_column(String(32))
    finding_codes: Mapped[list] = mapped_column(JSON, default=list)
    provider_called: Mapped[bool] = mapped_column(Boolean, default=False)
    provider_status: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)


# Engine and sessionmaker singletons
_engine = None
_sessionmaker = None


def get_engine():
    """Get or create the SQLAlchemy engine."""
    global _engine
    if _engine is None:
        settings = get_settings()
        connect_args = {"check_same_thread": False} if "sqlite" in settings.database_url else {}
        _engine = create_engine(
            settings.database_url,
            connect_args=connect_args,
            echo=False,
            future=True,
        )
    return _engine


def get_sessionmaker():
    """Get or create the session factory."""
    global _sessionmaker
    if _sessionmaker is None:
        engine = get_engine()
        _sessionmaker = sessionmaker(
            bind=engine,
            expire_on_commit=False,
        )
    return _sessionmaker


def init_db() -> None:
    """Initialize database tables."""
    engine = get_engine()
    Base.metadata.create_all(bind=engine)


def get_db_session() -> Generator[Session, None, None]:
    """Dependency for obtaining a database session."""
    session_factory = get_sessionmaker()
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
