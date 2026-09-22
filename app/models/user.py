"""
User Model
==========
Represents a student/user account.
Stores only cryptographic password hashes, never plaintext or reversible secrets.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    """User account entity adhering to least-privilege credential storage."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(String(32), unique=True, index=True, nullable=False)
    full_name = Column(String(128), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    password_history = relationship(
        "PasswordHistory",
        back_populates="user",
        cascade="all, delete-orphan",
        order_by="desc(PasswordHistory.created_at)",
    )
    sessions = relationship(
        "SessionModel",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    recovery_tokens = relationship(
        "RecoveryToken",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    security_events = relationship(
        "SecurityEvent",
        back_populates="user",
    )

    def is_locked(self) -> bool:
        """Check whether the account is currently locked out."""
        if self.locked_until is None:
            return False
        # Normalize timezone
        now = datetime.now(timezone.utc)
        lock_time = self.locked_until
        if lock_time.tzinfo is None:
            lock_time = lock_time.replace(tzinfo=timezone.utc)
        return now < lock_time
