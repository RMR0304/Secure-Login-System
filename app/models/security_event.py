"""
Security Event Audit Model
==========================
Records security-relevant system operations for auditing, intrusion detection,
and forensic verification. Explicitly strips any sensitive credentials.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class SecurityEvent(Base):
    """Audit log entry for security and authentication tracking."""

    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    event_time = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    success = Column(Boolean, default=True, nullable=False)
    details = Column(Text, nullable=True)

    user = relationship("User", back_populates="security_events")
