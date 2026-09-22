"""
User and Dashboard Router
=========================
Serves the student dashboard and user metadata inspection endpoints.
Guarantees that sensitive credentials and raw hashes are never exposed.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.models.security_event import SecurityEvent
from app.schemas.auth import UserResponse
from app.middleware.security import get_current_user, get_current_user_optional

router = APIRouter(tags=["User"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Render student dashboard for authenticated users.
    Redirects unauthenticated visitors to login page.
    """
    if not current_user:
        return RedirectResponse(url="/login?unauthorized=1", status_code=status.HTTP_302_FOUND)

    # Retrieve recent security events for user's audit timeline
    recent_events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.user_id == current_user.id)
        .order_by(SecurityEvent.event_time.desc())
        .limit(10)
        .all()
    )

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user": current_user,
            "recent_events": recent_events,
        },
    )


@router.get("/api/me", response_model=UserResponse)
async def get_my_profile(
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve profile details for current authenticated session.
    Plaintext passwords, password hashes, and tokens are omitted.
    """
    return UserResponse.model_validate(current_user)
