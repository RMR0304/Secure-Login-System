"""
Authentication Pydantic Schemas
===============================
Defines strongly-typed request and response structures for registration and login.
"""

from datetime import datetime
from typing import Optional
import re
from pydantic import BaseModel, Field, field_validator, model_validator


class UserRegisterRequest(BaseModel):
    """Schema for new user registration."""

    full_name: str = Field(..., min_length=2, max_length=128, description="Full student name")
    student_id: str = Field(..., min_length=3, max_length=32, description="Unique student identification code")
    email: str = Field(..., max_length=255, description="Institutional email address")
    password: str = Field(..., min_length=12, max_length=128, description="User password")
    confirm_password: str = Field(..., min_length=12, max_length=128, description="Password confirmation")

    @field_validator("student_id")
    @classmethod
    def validate_student_id(cls, v: str) -> str:
        cleaned = v.strip()
        if not re.match(r"^[A-Za-z0-9_-]+$", cleaned):
            raise ValueError("Student ID may only contain alphanumeric characters, underscores, and hyphens.")
        return cleaned

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        cleaned = v.strip().lower()
        # RFC 5322 simplified pattern
        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", cleaned):
            raise ValueError("Invalid email format.")
        return cleaned

    @model_validator(mode="after")
    def verify_password_match(self) -> "UserRegisterRequest":
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match.")
        return self


class UserLoginRequest(BaseModel):
    """Schema for user authentication request."""

    email: str = Field(..., description="Registered email address")
    password: str = Field(..., min_length=1, max_length=128, description="Password")

    @field_validator("email")
    @classmethod
    def clean_email(cls, v: str) -> str:
        return v.strip().lower()

class UserResponse(BaseModel):
    """Public representation of user account. Plaintext passwords and hashes are omitted."""

    model_config = {"from_attributes": True}

    id: int
    student_id: str
    full_name: str
    email: str
    is_active: bool
    failed_login_attempts: int
    locked_until: Optional[datetime] = None
    created_at: datetime
    last_login_at: Optional[datetime] = None


class LoginResponse(BaseModel):
    """Successful login response structure."""

    message: str
    user: UserResponse
