"""
Password Management Schemas
===========================
Defines schemas for password change operations and policy validation responses.
"""

from typing import List
from pydantic import BaseModel, Field, model_validator


class PasswordChangeRequest(BaseModel):
    """Schema for updating an existing user's password."""

    current_password: str = Field(..., min_length=1, max_length=128, description="Current active password")
    new_password: str = Field(..., min_length=12, max_length=128, description="Proposed new password")
    confirm_new_password: str = Field(..., min_length=12, max_length=128, description="Confirmation of new password")

    @model_validator(mode="after")
    def verify_passwords_match(self) -> "PasswordChangeRequest":
        if self.new_password != self.confirm_new_password:
            raise ValueError("New password and confirmation do not match.")
        if self.current_password == self.new_password:
            raise ValueError("New password must be different from current password.")
        return self


class PasswordPolicyValidationResponse(BaseModel):
    """Result of evaluating password complexity rules."""

    is_valid: bool
    violations: List[str] = Field(default_factory=list)
