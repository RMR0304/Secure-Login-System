"""
FastAPI Application Entry Point
===============================
Configures middleware, exception handlers, static assets, templates, and routing.
Guarantees defensive error handling with zero stack-trace leakage.
"""

import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import RequestValidationError
from app.config import get_settings
from app.database import engine, Base
from app.middleware.security import SecurityHeadersMiddleware
from app.routers import auth_router, users_router, password_router, recovery_router

logger = logging.getLogger("app.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager: ensures data directory and database schema exist."""
    os.makedirs("./data", exist_ok=True)
    Base.metadata.create_all(bind=engine)
    logger.info("Database schemas verified and initialized.")
    yield


app = FastAPI(
    title="Secure Campus Portal",
    description="HCLTech Cybersecurity Practical Assessment: Secure Password Storage",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Apply Security Headers Middleware
app.add_middleware(SecurityHeadersMiddleware)

# Mount Static Assets & Templates
os.makedirs("app/static/css", exist_ok=True)
os.makedirs("app/static/js", exist_ok=True)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

templates = Jinja2Templates(directory="app/templates")

# Mount Application Routers
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(password_router)
app.include_router(recovery_router)


# --- Centralized Secure Exception Handlers ---

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions safely for both API and browser requests."""
    # If the client requested HTML and this is not an /api route, render error page
    accept = request.headers.get("accept", "")
    if "text/html" in accept and not request.url.path.startswith("/api/"):
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            context={
                "status_code": exc.status_code,
                "detail": exc.detail,
                "user": None,
            },
            status_code=exc.status_code,
        )

    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Sanitize validation errors to prevent internal architecture disclosure."""
    errors = []
    for err in exc.errors():
        field = ".".join(str(loc) for loc in err.get("loc", []) if loc != "body")
        msg = err.get("msg", "Invalid input value.")
        # Strip ValueError prefix if present
        if msg.startswith("Value error, "):
            msg = msg.replace("Value error, ", "")
        errors.append(f"{field}: {msg}" if field else msg)

    clean_message = " | ".join(errors)
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": clean_message},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch-all exception handler.
    Prevents exposure of Python stack traces, SQL syntax, or internal system paths.
    """
    logger.error("Unhandled system exception on %s: %s", request.url.path, str(exc), exc_info=True)

    accept = request.headers.get("accept", "")
    if "text/html" in accept and not request.url.path.startswith("/api/"):
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            context={
                "status_code": 500,
                "detail": "An internal error occurred while processing your request. Please try again later.",
                "user": None,
            },
            status_code=500,
        )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal error occurred. Please contact the system administrator."},
    )
