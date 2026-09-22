"""
Authentication Service
======================
Implements user registration, credential verification, account lockout logic,
password changes, and history tracking.
Enforces generic error messages to eliminate username/email enumeration vulnerabilities.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List
from sqlalchemy.orm import Session
from app.config import get_settings
from app.models.user import User
from app.models.password_history import PasswordHistory
from app.schemas.auth import UserRegisterRequest
from app.services.password_service import PasswordService
from app.services.session_service import SessionService
from app.services.audit_service import AuditService

# Pre-computed dummy Argon2id hash to mitigate timing attacks when user does not exist
DUMMY_HASH = "$argon2id$v=19$m=65536,t=2,p=2$dHVtbXlfc2FsdF8xNl9ieXRl$7iS7f9eBqvM03Z6gQJ1kGqX5nL+5wK3Zl9XbZc+1a8o"


class AuthService:
    """Authentication and credential management coordinator."""

    def __init__(self):
        self.password_service = PasswordService()

    def register_user(
        self,
        db: Session,
        req: UserRegisterRequest,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[bool, Optional[User], str]:
        """
        Register a new user account.
        Validates uniqueness of email and student ID, validates password policy,
        hashes password via Argon2id with unique salt, and persists record.
        """
        # Validate unique email
        existing_email = db.query(User).filter(User.email == req.email).first()
        if existing_email:
            AuditService.log_event(
                db,
                event_type="REGISTRATION_FAILURE",
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "Email already registered", "email": req.email},
            )
            return False, None, "An account with this email address already exists."

        # Validate unique student ID
        existing_sid = db.query(User).filter(User.student_id == req.student_id).first()
        if existing_sid:
            AuditService.log_event(
                db,
                event_type="REGISTRATION_FAILURE",
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "Student ID already registered", "student_id": req.student_id},
            )
            return False, None, "An account with this Student ID already exists."

        # Validate password policy
        is_valid, violations = self.password_service.validate_password_policy(
            req.password, email=req.email, student_id=req.student_id
        )
        if not is_valid:
            AuditService.log_event(
                db,
                event_type="REGISTRATION_FAILURE",
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "Password policy violations"},
            )
            return False, None, " ".join(violations)

        # Hash password using Argon2id with unique salt
        argon2_hash = self.password_service.hash_password(req.password)

        now = datetime.now(timezone.utc)
        user = User(
            student_id=req.student_id,
            full_name=req.full_name,
            email=req.email,
            password_hash=argon2_hash,
            failed_login_attempts=0,
            locked_until=None,
            is_active=True,
            created_at=now,
            updated_at=now,
            last_login_at=None,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        AuditService.log_event(
            db,
            event_type="REGISTRATION_SUCCESS",
            success=True,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"student_id": user.student_id},
        )

        return True, user, "Registration successful."

    def authenticate_user(
        self,
        db: Session,
        email: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[bool, Optional[User], str, int]:
        """
        Authenticate user with constant-time verification and account lockout handling.
        Returns: (success, user, message, http_status_code)
        """
        settings = get_settings()
        clean_email = email.strip().lower()

        user = db.query(User).filter(User.email == clean_email).first()

        if not user:
            # Perform dummy verification to mitigate user-enumeration timing attacks
            self.password_service.verify_password(DUMMY_HASH, password)
            AuditService.log_event(
                db,
                event_type="LOGIN_FAILURE",
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "Invalid credentials", "email": clean_email},
            )
            return False, None, "Authentication failed. Invalid email or password.", 401

        now = datetime.now(timezone.utc)

        # Check account lockout status
        if user.is_locked():
            AuditService.log_event(
                db,
                event_type="ACCOUNT_LOCKED",
                success=False,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "Attempt during active lockout window"},
            )
            return (
                False,
                None,
                f"Account is temporarily locked due to repeated failed login attempts. Please try again after {settings.LOCKOUT_DURATION_MINUTES} minutes or initiate account recovery.",
                423,
            )

        # If lockout window has expired, reset counter before proceeding
        if user.locked_until is not None and not user.is_locked():
            user.failed_login_attempts = 0
            user.locked_until = None
            db.commit()

        # Constant-time Argon2id password verification
        is_password_valid = self.password_service.verify_password(user.password_hash, password)

        if not is_password_valid:
            user.failed_login_attempts += 1
            is_now_locked = False

            if user.failed_login_attempts >= settings.LOCKOUT_MAX_ATTEMPTS:
                user.locked_until = now + timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
                is_now_locked = True
                AuditService.log_event(
                    db,
                    event_type="ACCOUNT_LOCKED",
                    success=False,
                    user_id=user.id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={"failed_attempts": user.failed_login_attempts, "duration_minutes": settings.LOCKOUT_DURATION_MINUTES},
                )
            else:
                AuditService.log_event(
                    db,
                    event_type="LOGIN_FAILURE",
                    success=False,
                    user_id=user.id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={"failed_attempts": user.failed_login_attempts},
                )

            db.commit()

            if is_now_locked:
                return (
                    False,
                    None,
                    f"Account has been locked due to {settings.LOCKOUT_MAX_ATTEMPTS} consecutive failed login attempts. Try again in {settings.LOCKOUT_DURATION_MINUTES} minutes.",
                    423,
                )

            return False, None, "Authentication failed. Invalid email or password.", 401

        # Successful authentication: reset failed attempt counter and update last login
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = now
        db.commit()

        AuditService.log_event(
            db,
            event_type="LOGIN_SUCCESS",
            success=True,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"status": "Authenticated"},
        )

        return True, user, "Login successful.", 200

    def change_password(
        self,
        db: Session,
        user: User,
        current_password: str,
        new_password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[bool, str, int]:
        """
        Change authenticated user's password.
        Validates current password, enforces policy, checks last-3 history,
        saves old hash in history, and revokes prior sessions.
        """
        # Verify current password
        if not self.password_service.verify_password(user.password_hash, current_password):
            AuditService.log_event(
                db,
                event_type="PASSWORD_CHANGE_FAILED",
                success=False,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "Incorrect current password"},
            )
            return False, "Current password is incorrect.", 400

        # Validate new password policy
        is_valid, violations = self.password_service.validate_password_policy(
            new_password, email=user.email, student_id=user.student_id
        )
        if not is_valid:
            AuditService.log_event(
                db,
                event_type="PASSWORD_CHANGE_FAILED",
                success=False,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "New password violates complexity policy"},
            )
            return False, " ".join(violations), 400

        # Retrieve last 3 password hashes from history (deterministic ID ordering)
        history_records = (
            db.query(PasswordHistory)
            .filter(PasswordHistory.user_id == user.id)
            .order_by(PasswordHistory.id.desc())
            .limit(3)
            .all()
        )
        history_hashes = [h.password_hash for h in history_records]

        # Check for reuse against current password and last-3 history
        if self.password_service.is_password_reused(new_password, user.password_hash, history_hashes):
            AuditService.log_event(
                db,
                event_type="PASSWORD_CHANGE_FAILED",
                success=False,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "Password matches current or historical password"},
            )
            return False, "New password cannot match your current password or your last 3 passwords.", 400

        now = datetime.now(timezone.utc)

        # Store current password hash in history
        history_entry = PasswordHistory(
            user_id=user.id,
            password_hash=user.password_hash,
            created_at=now,
        )
        db.add(history_entry)
        db.flush()

        # Prune older history beyond 3 entries
        all_history = (
            db.query(PasswordHistory)
            .filter(PasswordHistory.user_id == user.id)
            .order_by(PasswordHistory.id.desc())
            .all()
        )
        if len(all_history) > 3:
            for old_h in all_history[3:]:
                db.delete(old_h)
            db.flush()

        # Hash new password with Argon2id and update user record
        user.password_hash = self.password_service.hash_password(new_password)
        user.updated_at = now

        # Revoke other existing sessions
        SessionService.revoke_all_user_sessions(db, user.id)

        db.commit()

        AuditService.log_event(
            db,
            event_type="PASSWORD_CHANGED",
            success=True,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"action": "Password successfully updated"},
        )

        return True, "Password changed successfully. Please log in with your new password.", 200
