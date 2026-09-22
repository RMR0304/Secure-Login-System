"""
Authentication Router
=====================
Handles user registration, login, logout, and frontend landing views.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Request, Response, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.config import get_settings
from app.database import get_db
from app.models.user import User
from app.schemas.auth import (
    UserRegisterRequest,
    UserLoginRequest,
    UserResponse,
    LoginResponse,
)
from app.services.auth_service import AuthService
from app.services.session_service import SessionService
from app.services.audit_service import AuditService
from app.middleware.security import SESSION_COOKIE_NAME, get_current_user_optional

router = APIRouter(tags=["Authentication"])
templates = Jinja2Templates(directory="app/templates")
auth_service = AuthService()


# --- HTML Page Routes ---

@router.get("/", response_class=HTMLResponse)
async def root(request: Request, current_user: Optional[User] = Depends(get_current_user_optional)):
    """Landing page: redirect to dashboard if logged in, else login."""
    if current_user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, current_user: Optional[User] = Depends(get_current_user_optional)):
    """Render cybersecurity-themed login page."""
    if current_user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="login.html", context={"user": None})


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, current_user: Optional[User] = Depends(get_current_user_optional)):
    """Render user registration page with real-time policy guidelines."""
    if current_user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="register.html", context={"user": None})


@router.get("/logout", response_class=HTMLResponse)
async def html_logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """HTML logout action: revokes session, clears cookie, redirects to login."""
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        SessionService.revoke_session(db, token)
        AuditService.log_event(
            db,
            event_type="LOGOUT",
            success=True,
            user_id=(current_user.id if current_user else None),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details={"action": "User initiated logout via GET"},
        )
    redirect = RedirectResponse(url="/login?logged_out=1", status_code=status.HTTP_302_FOUND)
    redirect.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
    )
    return redirect


# --- JSON API Endpoints ---

@router.post("/api/auth/register", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
async def api_register(
    req: UserRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Register a new student user.
    Validates input, enforces password policy, derives Argon2id hash with unique salt,
    and returns sanitized user representation.
    """
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")

    success, user, message = auth_service.register_user(
        db=db,
        req=req,
        ip_address=ip_addr,
        user_agent=user_agent,
    )

    if not success:
        if "already exists" in message:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=message)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

    return LoginResponse(
        message="User account registered successfully.",
        user=UserResponse.model_validate(user),
    )


@router.post("/api/auth/login", response_model=LoginResponse)
async def api_login(
    req: UserLoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Authenticate user credentials.
    Performs constant-time Argon2id verification, tracks consecutive failures,
    and enforces account lockout. Sets HttpOnly session cookie on success.
    """
    settings = get_settings()
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown")

    success, user, message, code = auth_service.authenticate_user(
        db=db,
        email=req.email,
        password=req.password,
        ip_address=ip_addr,
        user_agent=user_agent,
    )

    if not success or not user:
        raise HTTPException(status_code=code, detail=message)

    # Generate server-side session and cookie
    raw_token, session_entry = SessionService.create_session(db, user)

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=settings.SESSION_EXPIRE_MINUTES * 60,
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        path="/",
    )

    return LoginResponse(
        message="Authentication successful.",
        user=UserResponse.model_validate(user),
    )


@router.post("/api/auth/logout")
async def api_logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    """
    Invalidate active session and clear authentication cookie.
    """
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        SessionService.revoke_session(db, token)
        AuditService.log_event(
            db,
            event_type="LOGOUT",
            success=True,
            user_id=(current_user.id if current_user else None),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details={"action": "User initiated API logout"},
        )

    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
    )
    return {"message": "Session successfully invalidated."}
