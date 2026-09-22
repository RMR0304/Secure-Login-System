"""
Security Audit Service
======================
Records critical authentication and authorization events to the database.
Guarantees that sensitive credentials (passwords, tokens, keys) are NEVER logged.
"""

import logging
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session
from app.models.security_event import SecurityEvent

logger = logging.getLogger("security_audit")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# Explicit blacklist of fields that must NEVER appear in audit details
SENSITIVE_KEYS = {
    "password",
    "confirm_password",
    "current_password",
    "new_password",
    "confirm_new_password",
    "token",
    "recovery_token",
    "session_token",
    "session_token_hash",
    "raw_token",
    "secret",
}


class AuditService:
    """Security audit logging manager."""

    @staticmethod
    def _sanitize_details(details: Optional[Dict[str, Any]]) -> str:
        """Strip sensitive credentials from event details before persistent storage."""
        if not details:
            return ""
        sanitized = {}
        for key, value in details.items():
            if any(sens in key.lower() for sens in SENSITIVE_KEYS):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = str(value)
        # Convert dictionary to key-value string
        return "; ".join(f"{k}={v}" for k, v in sanitized.items())

    @classmethod
    def log_event(
        cls,
        db: Session,
        event_type: str,
        success: bool = True,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> SecurityEvent:
        """Record an immutable security event."""
        sanitized_details = cls._sanitize_details(details)

        event = SecurityEvent(
            user_id=user_id,
            event_type=event_type,
            ip_address=ip_address or "127.0.0.1",
            user_agent=(user_agent[:255] if user_agent else "Unknown"),
            success=success,
            details=sanitized_details,
        )
        try:
            db.add(event)
            db.commit()
            db.refresh(event)
        except Exception as e:
            db.rollback()
            logger.error("Failed to commit security event: %s", str(e))

        log_msg = f"EVENT: {event_type} | User: {user_id or 'Anonymous'} | Success: {success} | Details: {sanitized_details}"
        if success:
            logger.info(log_msg)
        else:
            logger.warning(log_msg)

        return event
