"""
Password Management Router
==========================
Handles password change requests, policy checks, and password history enforcement.
"""

from typing import Optional, Dict
from fastapi import APIRouter, Depends, Request, Response, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.schemas.password import (
    PasswordChangeRequest,
    PasswordPolicyValidationResponse,
)
from app.services.auth_service import AuthService
from app.services.password_service import PasswordService
from app.middleware.security import (
    SESSION_COOKIE_NAME,
    get_current_user,
    get_current_user_optional,
)

router = APIRouter(tags=["Password Management"])
templates = Jinja2Templates(directory="app/templates")
auth_service = AuthService()
password_service = PasswordService()


@router.get("/change-password", response_class=HTMLResponse)
async def change_password_page(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """Render password modification interface for authenticated users."""
    if not current_user:
        return RedirectResponse(url="/login?unauthorized=1", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse(
        request=request,
        name="change_password.html",
        context={"user": current_user},
    )


@router.post("/api/auth/change-password")
async def api_change_password(
    req: PasswordChangeRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Update password for authenticated user.
    Enforces current password verification, complexity rules, and last-three history restriction.
    Invalidates current session requiring fresh login.
    """
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")

    success, message, code = auth_service.change_password(
        db=db,
        user=current_user,
        current_password=req.current_password,
        new_password=req.new_password,
        ip_address=ip_addr,
        user_agent=user_agent,
    )

    if not success:
        raise HTTPException(status_code=code, detail=message)

    # Invalidate session cookie to require fresh login
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
    )

    return {"message": message}


@router.post("/api/auth/validate-policy", response_model=PasswordPolicyValidationResponse)
async def api_validate_policy(payload: Dict[str, str]):
    """Client helper endpoint to validate candidate password against policy rules in real time."""
    password = payload.get("password", "")
    email = payload.get("email")
    student_id = payload.get("student_id")

    is_valid, violations = password_service.validate_password_policy(
        password=password, email=email, student_id=student_id
    )

    return PasswordPolicyValidationResponse(
        is_valid=is_valid,
        violations=violations,
    )
