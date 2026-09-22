"""
Account Recovery Service
========================
Handles password recovery workflows using short-lived, single-use cryptographic tokens.
Tokens are stored as SHA-256 hashes and enforced strictly for local educational use.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from sqlalchemy.orm import Session
from app.config import get_settings
from app.models.recovery_token import RecoveryToken
from app.models.user import User
from app.models.password_history import PasswordHistory
from app.services.password_service import PasswordService
from app.services.session_service import SessionService
from app.services.audit_service import AuditService


class RecoveryService:
    """Password recovery and reset manager."""

    @staticmethod
    def _hash_token(token: str) -> str:
        """Hash raw recovery token using SHA-256."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @classmethod
    def initiate_recovery(
        cls,
        db: Session,
        identifier: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Optional[User]]:
        """
        Initiate password recovery for a user identified by email or student ID.
        Returns (success, raw_token_if_found, user).
        In production, the raw token is dispatched via email. For local assessment/demo,
        it is provided to the caller for simulated presentation.
        """
        settings = get_settings()
        clean_id = identifier.strip().lower()

        # Look up user by email or student_id
        user = (
            db.query(User)
            .filter((User.email == clean_id) | (User.student_id == clean_id))
            .first()
        )

        if not user or not user.is_active:
            # Generic response pattern avoids account enumeration
            AuditService.log_event(
                db,
                event_type="RECOVERY_REQUESTED",
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"identifier": clean_id, "reason": "User not found or inactive"},
            )
            return False, None, None

        # Invalidate any existing unused recovery tokens for this user
        now = datetime.now(timezone.utc)
        db.query(RecoveryToken).filter(
            RecoveryToken.user_id == user.id,
            RecoveryToken.used_at.is_(None),
        ).update({"used_at": now})

        # Generate fresh token
        raw_token = secrets.token_urlsafe(32)
        token_hash = cls._hash_token(raw_token)
        expires_at = now + timedelta(minutes=settings.RECOVERY_TOKEN_EXPIRE_MINUTES)

        recovery_entry = RecoveryToken(
            user_id=user.id,
            token_hash=token_hash,
            created_at=now,
            expires_at=expires_at,
            used_at=None,
        )
        db.add(recovery_entry)
        db.commit()

        AuditService.log_event(
            db,
            event_type="RECOVERY_REQUESTED",
            success=True,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"action": "Recovery token issued", "expires_in_minutes": settings.RECOVERY_TOKEN_EXPIRE_MINUTES},
        )

        return True, raw_token, user

    @classmethod
    def verify_token(cls, db: Session, raw_token: str) -> Tuple[bool, Optional[User], str]:
        """
        Inspect token validity without consuming it.
        Returns (is_valid, user, message).
        """
        if not raw_token or len(raw_token.strip()) < 16:
            return False, None, "Invalid recovery token format."

        token_hash = cls._hash_token(raw_token.strip())
        entry = db.query(RecoveryToken).filter(RecoveryToken.token_hash == token_hash).first()

        if not entry:
            return False, None, "Recovery token does not exist."

        if entry.used_at is not None:
            return False, None, "Recovery token has already been used."

        now = datetime.now(timezone.utc)
        exp = entry.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)

        if now >= exp:
            return False, None, "Recovery token has expired."

        user = db.query(User).filter(User.id == entry.user_id).first()
        if not user or not user.is_active:
            return False, None, "Account is disabled."

        return True, user, "Token is valid."

    @classmethod
    def reset_password(
        cls,
        db: Session,
        raw_token: str,
        new_password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """
        Reset user password using a valid, unused, non-expired recovery token.
        Enforces password complexity and last-three history rules.
        """
        is_valid, user, msg = cls.verify_token(db, raw_token)
        if not is_valid or not user:
            AuditService.log_event(
                db,
                event_type="RECOVERY_FAILURE",
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": msg},
            )
            return False, msg

        pwd_service = PasswordService()

        # Validate password policy
        valid_policy, violations = pwd_service.validate_password_policy(
            new_password, email=user.email, student_id=user.student_id
        )
        if not valid_policy:
            AuditService.log_event(
                db,
                event_type="RECOVERY_FAILURE",
                success=False,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "Password policy violation"},
            )
            return False, " ".join(violations)

        # Retrieve password history (last 3 entries, deterministic ID ordering)
        history_entries = (
            db.query(PasswordHistory)
            .filter(PasswordHistory.user_id == user.id)
            .order_by(PasswordHistory.id.desc())
            .limit(3)
            .all()
        )
        history_hashes = [h.password_hash for h in history_entries]

        # Check for password reuse against current and historical passwords
        if pwd_service.is_password_reused(new_password, user.password_hash, history_hashes):
            AuditService.log_event(
                db,
                event_type="RECOVERY_FAILURE",
                success=False,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "Password matches current or recent history"},
            )
            return False, "New password cannot match your current password or your last 3 passwords."

        # Add current password hash to history
        now = datetime.now(timezone.utc)
        history_record = PasswordHistory(
            user_id=user.id,
            password_hash=user.password_hash,
            created_at=now,
        )
        db.add(history_record)
        db.flush()

        # Prune older history beyond the last 3 items
        all_history = (
            db.query(PasswordHistory)
            .filter(PasswordHistory.user_id == user.id)
            .order_by(PasswordHistory.id.desc())
            .all()
        )
        # Note: We just added one, so keep top 3, delete remaining
        if len(all_history) > 3:
            for old_h in all_history[3:]:
                db.delete(old_h)
            db.flush()

        # Hash new password with Argon2id
        user.password_hash = pwd_service.hash_password(new_password)
        user.failed_login_attempts = 0
        user.locked_until = None
        user.updated_at = now

        # Mark token as used
        token_hash = cls._hash_token(raw_token.strip())
        token_entry = db.query(RecoveryToken).filter(RecoveryToken.token_hash == token_hash).first()
        if token_entry:
            token_entry.used_at = now

        # Invalidate all active sessions to prevent session hijacking
        SessionService.revoke_all_user_sessions(db, user.id)

        db.commit()

        AuditService.log_event(
            db,
            event_type="RECOVERY_SUCCESS",
            success=True,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"action": "Password successfully reset via recovery token"},
        )

        return True, "Password reset successfully. You may now log in with your new password."
