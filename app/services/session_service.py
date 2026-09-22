"""
Session Management Service
==========================
Manages server-side authenticated sessions using SHA-256 token hashing.
Raw session tokens are returned to the client as HttpOnly cookies and never
stored unhashed in the database.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from sqlalchemy.orm import Session
from app.config import get_settings
from app.models.session import SessionModel
from app.models.user import User


class SessionService:
    """Server-side session management."""

    @staticmethod
    def _hash_token(raw_token: str) -> str:
        """Hash raw session token using SHA-256 for secure database indexing."""
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    @classmethod
    def create_session(cls, db: Session, user: User) -> Tuple[str, SessionModel]:
        """
        Create a new authenticated session for a user.
        Generates 256-bit cryptographically secure token and stores its SHA-256 hash.
        """
        settings = get_settings()
        raw_token = secrets.token_urlsafe(32)
        token_hash = cls._hash_token(raw_token)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=settings.SESSION_EXPIRE_MINUTES)

        session_entry = SessionModel(
            user_id=user.id,
            session_token_hash=token_hash,
            created_at=now,
            expires_at=expires_at,
            revoked_at=None,
        )
        db.add(session_entry)
        db.commit()
        db.refresh(session_entry)

        return raw_token, session_entry

    @classmethod
    def get_user_from_token(cls, db: Session, raw_token: Optional[str]) -> Optional[User]:
        """Validate raw token against stored session hash and retrieve active user."""
        if not raw_token:
            return None

        token_hash = cls._hash_token(raw_token)
        session_entry = (
            db.query(SessionModel)
            .filter(SessionModel.session_token_hash == token_hash)
            .first()
        )

        if not session_entry or not session_entry.is_valid():
            return None

        user = db.query(User).filter(User.id == session_entry.user_id, User.is_active == True).first()
        return user

    @classmethod
    def revoke_session(cls, db: Session, raw_token: Optional[str]) -> bool:
        """Revoke a specific active session."""
        if not raw_token:
            return False

        token_hash = cls._hash_token(raw_token)
        session_entry = (
            db.query(SessionModel)
            .filter(SessionModel.session_token_hash == token_hash)
            .first()
        )

        if session_entry and session_entry.revoked_at is None:
            session_entry.revoked_at = datetime.now(timezone.utc)
            db.commit()
            return True
        return False

    @classmethod
    def revoke_all_user_sessions(cls, db: Session, user_id: int) -> int:
        """Invalidate all active sessions for a user (e.g., upon password reset)."""
        now = datetime.now(timezone.utc)
        count = (
            db.query(SessionModel)
            .filter(SessionModel.user_id == user_id, SessionModel.revoked_at.is_(None))
            .update({"revoked_at": now})
        )
        db.commit()
        return count
