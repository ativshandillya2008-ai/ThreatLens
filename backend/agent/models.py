"""SQLAlchemy models for AI Agent chat history and session persistence."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from ..database import Base


class AgentChatSession(Base):
    """A conversation thread between the user and the ThreatLens Agent."""
    __tablename__ = "agent_chat_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_email = Column(String(255), nullable=False, index=True)
    title = Column(String(255), nullable=False, default="New Conversation")
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    messages = relationship(
        "AgentChatMessage",
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="AgentChatMessage.created_at",
        lazy="selectin",
    )


class AgentChatMessage(Base):
    """An individual message (user prompt or agent response) in a chat session."""
    __tablename__ = "agent_chat_messages"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(
        String(36),
        ForeignKey("agent_chat_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role = Column(String(32), nullable=False)  # "user" | "assistant"
    content = Column(Text, nullable=False)
    tools_called = Column(Text, nullable=True)  # JSON-encoded array of tool invocations
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    session = relationship("AgentChatSession", back_populates="messages")
