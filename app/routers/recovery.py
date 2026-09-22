"""
Account Recovery Router
========================
Handles self-service account recovery and password reset.
Includes clearly identified simulated delivery for local educational evaluation.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Request, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.config import get_settings
from app.database import get_db
from app.models.user import User
from app.schemas.recovery import (
    RecoveryInitiateRequest,
    RecoveryVerifyRequest,
    RecoveryResetRequest,
)
from app.services.recovery_service import RecoveryService
from app.middleware.security import get_current_user_optional

router = APIRouter(tags=["Account Recovery"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/recover", response_class=HTMLResponse)
async def recovery_page(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """Render account recovery and reset interface."""
    return templates.TemplateResponse(
        request=request,
        name="recovery.html",
        context={"user": current_user},
    )


@router.post("/api/auth/recovery/request")
async def api_recovery_request(
    req: RecoveryInitiateRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Request a single-use password recovery token.
    For local testing and academic demonstration, displays token directly with
    clear DEVELOPMENT / LOCAL TESTING ONLY indicator.
    """
    settings = get_settings()
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")

    success, raw_token, user = RecoveryService.initiate_recovery(
        db=db,
        identifier=req.identifier,
        ip_address=ip_addr,
        user_agent=user_agent,
    )

    is_dev = settings.APP_ENV in ("development", "testing")

    if is_dev and raw_token:
        return {
            "message": "Recovery token generated successfully.",
            "dev_token": raw_token,
            "is_dev": True,
            "note": "DEVELOPMENT / LOCAL TESTING ONLY: In production, this token is transmitted strictly via authenticated email/SMS.",
            "expires_in_minutes": settings.RECOVERY_TOKEN_EXPIRE_MINUTES,
        }

    return {
        "message": "If the account exists, recovery instructions have been initiated.",
        "is_dev": False,
    }


@router.post("/api/auth/recovery/verify")
async def api_recovery_verify(
    req: RecoveryVerifyRequest,
    db: Session = Depends(get_db),
):
    """Verify validity of candidate recovery token before presenting reset form."""
    is_valid, user, message = RecoveryService.verify_token(db, req.token)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)
    return {"valid": True, "message": "Token is valid."}


@router.post("/api/auth/recovery/reset")
async def api_recovery_reset(
    req: RecoveryResetRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Consume single-use recovery token to set new password.
    Enforces complexity policy and last-three history constraints.
    """
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")

    success, message = RecoveryService.reset_password(
        db=db,
        raw_token=req.token,
        new_password=req.new_password,
        ip_address=ip_addr,
        user_agent=user_agent,
    )

    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

    return {"message": message}
