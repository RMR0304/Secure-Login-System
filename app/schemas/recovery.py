"""
Account Recovery Schemas
========================
Defines schemas for local synthetic password recovery initiation and resets.
"""

from pydantic import BaseModel, Field, field_validator, model_validator


class RecoveryInitiateRequest(BaseModel):
    """Request to generate a password reset authorization."""

    identifier: str = Field(..., min_length=3, max_length=255, description="Registered email or student ID")

    @field_validator("identifier")
    @classmethod
    def clean_identifier(cls, v: str) -> str:
        return v.strip().lower()


class RecoveryVerifyRequest(BaseModel):
    """Request to inspect/verify the validity of a recovery token."""

    token: str = Field(..., min_length=16, max_length=128, description="Cryptographic recovery token")


class RecoveryResetRequest(BaseModel):
    """Request to reset password using an authorized single-use token."""

    token: str = Field(..., min_length=16, max_length=128, description="Recovery token")
    new_password: str = Field(..., min_length=12, max_length=128, description="New password")
    confirm_new_password: str = Field(..., min_length=12, max_length=128, description="New password confirmation")

    @model_validator(mode="after")
    def verify_passwords_match(self) -> "RecoveryResetRequest":
        if self.new_password != self.confirm_new_password:
            raise ValueError("New password and confirmation do not match.")
        return self
