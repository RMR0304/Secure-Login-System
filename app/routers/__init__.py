"""FastAPI Routers Package."""

from app.routers.auth import router as auth_router
from app.routers.users import router as users_router
from app.routers.password import router as password_router
from app.routers.recovery import router as recovery_router

__all__ = [
    "auth_router",
    "users_router",
    "password_router",
    "recovery_router",
]
