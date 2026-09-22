"""
Password Service
================
Handles cryptographic password hashing and constant-time verification using Argon2id.
Implements password complexity policy validation and last-three password history checks.
Never stores or logs plaintext passwords or uses home-grown crypto.
"""

import re
from typing import List, Tuple, Optional
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from app.config import get_settings


class PasswordService:
    """Argon2id password hashing, verification, and policy enforcement service."""

    def __init__(self, time_cost: Optional[int] = None, memory_cost: Optional[int] = None, parallelism: Optional[int] = None):
        settings = get_settings()
        self.time_cost = time_cost or settings.ARGON2_TIME_COST
        self.memory_cost = memory_cost or settings.ARGON2_MEMORY_COST
        self.parallelism = parallelism or settings.ARGON2_PARALLELISM

        # Initialize Argon2id hasher with RFC 9106 recommended parameters
        # Argon2id combines resistance to GPU cracking and side-channel cache attacks.
        self._hasher = PasswordHasher(
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )

    def hash_password(self, password: str) -> str:
        """
        Hash plaintext password with Argon2id using a per-password random 16-byte salt.
        Returns the formatted string: $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>
        """
        if not password:
            raise ValueError("Password cannot be empty.")
        # argon2-cffi automatically generates a cryptographically secure unique salt
        return self._hasher.hash(password)

    def verify_password(self, stored_hash: str, password: str) -> bool:
        """
        Perform constant-time verification of password against stored Argon2id hash.
        Returns True if matching, False if mismatched, invalid, or corrupted.
        """
        if not stored_hash or not password:
            return False
        try:
            return self._hasher.verify(stored_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
        except Exception:
            return False

    def validate_password_policy(
        self,
        password: str,
        email: Optional[str] = None,
        student_id: Optional[str] = None,
    ) -> Tuple[bool, List[str]]:
        """
        Validates password against mandatory security policy:
        - Minimum length: 12 characters
        - Must contain at least one uppercase letter (A-Z)
        - Must contain at least one lowercase letter (a-z)
        - Must contain at least one digit (0-9)
        - Must contain at least one special character (!@#$%^&*...)
        - Must not contain user's email or username portion
        - Must not contain user's student ID
        """
        violations = []

        if len(password) < 12:
            violations.append("Password must be at least 12 characters in length.")

        if not re.search(r"[A-Z]", password):
            violations.append("Password must contain at least one uppercase letter (A-Z).")

        if not re.search(r"[a-z]", password):
            violations.append("Password must contain at least one lowercase letter (a-z).")

        if not re.search(r"[0-9]", password):
            violations.append("Password must contain at least one number (0-9).")

        if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`]", password):
            violations.append("Password must contain at least one special character.")

        pwd_lower = password.lower()

        # Check email inclusion
        if email:
            email_lower = email.strip().lower()
            if email_lower and email_lower in pwd_lower:
                violations.append("Password must not contain your email address.")
            # Check local part of email
            local_part = email_lower.split("@")[0]
            if len(local_part) >= 3 and local_part in pwd_lower:
                violations.append("Password must not contain the username portion of your email.")

        # Check student ID inclusion
        if student_id:
            sid_lower = student_id.strip().lower()
            if len(sid_lower) >= 3 and sid_lower in pwd_lower:
                violations.append("Password must not contain your student ID.")

        is_valid = len(violations) == 0
        return is_valid, violations

    def is_password_reused(
        self,
        new_password: str,
        current_hash: Optional[str],
        history_hashes: List[str],
    ) -> bool:
        """
        Check whether proposed new password matches the current password or any of
        the historical password hashes (last-three history).
        """
        # Check current password hash
        if current_hash and self.verify_password(current_hash, new_password):
            return True

        # Check each historical hash
        for historical_hash in history_hashes:
            if self.verify_password(historical_hash, new_password):
                return True

        return False
