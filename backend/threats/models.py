"""SQLAlchemy models for threat scores and audit overrides.

All ThreatScore records are append-only: no row is ever UPDATE'd or DELETE'd
after insertion. AuditOverride records user actions on scored messages.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from ..database import Base


class ThreatScore(Base):
    """Append-only threat analysis record for a single email."""
    __tablename__ = "threat_scores"
    __table_args__ = (
        UniqueConstraint("user_email", "message_id", name="uq_user_message"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_email = Column(String(255), nullable=False, index=True)
    message_id = Column(String(255), nullable=False, index=True)

    # Email metadata
    subject = Column(Text, nullable=True)
    sender = Column(Text, nullable=True)
    received_at = Column(DateTime(timezone=True), nullable=True)
    analyzed_at = Column(DateTime(timezone=True), nullable=False)

    # Authentication stage
    spf_result = Column(String(32), default="none")
    dkim_result = Column(String(32), default="none")
    dmarc_result = Column(String(32), default="none")
    auth_score = Column(Float, default=0.0)

    # GeoIP stage
    geo_country = Column(String(128), nullable=True)
    geo_asn = Column(String(64), nullable=True)
    geo_org = Column(String(256), nullable=True)
    geo_lat = Column(Float, nullable=True)
    geo_lon = Column(Float, nullable=True)
    geo_mismatch = Column(Boolean, default=False)
    geo_score = Column(Float, default=0.0)
    geo_hops = Column(Text, nullable=True)          # JSON array

    # LLM stage
    llm_score = Column(Float, default=0.0)
    llm_threat_type = Column(String(64), nullable=True)
    llm_reasoning = Column(Text, nullable=True)     # JSON array of bullets
    llm_suspicious_phrases = Column(Text, nullable=True)  # JSON array

    # Safe Browsing stage
    urls_checked = Column(Text, nullable=True)      # JSON array
    unsafe_urls = Column(Text, nullable=True)        # JSON object {url: threat_type}
    url_score = Column(Float, default=0.0)

    # Final verdict
    final_score = Column(Float, nullable=False, index=True)
    severity = Column(
        Enum("LOW", "MEDIUM", "HIGH", name="severity_enum"),
        nullable=False,
        index=True,
    )
    quarantined = Column(Boolean, default=False)

    # Forensic storage (encrypted)
    raw_headers_encrypted = Column(Text, nullable=True)

    # Override relationship
    overrides = relationship("AuditOverride", back_populates="threat_score", lazy="select")


class AuditOverride(Base):
    """User override actions on flagged emails."""
    __tablename__ = "audit_overrides"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    threat_score_id = Column(
        String(36),
        ForeignKey("threat_scores.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    user_email = Column(String(255), nullable=False, index=True)
    override_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    action = Column(
        Enum("release", "confirm", name="override_action_enum"),
        nullable=False,
    )
    reason = Column(Text, nullable=True)

    threat_score = relationship("ThreatScore", back_populates="overrides")
