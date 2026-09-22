"""
Application Entry Point
=======================
Starts the Secure Password Storage Campus Portal via Uvicorn.
"""

import sys
import uvicorn
from app.config import get_settings

if __name__ == "__main__":
    settings = get_settings()
    print(f"[*] Starting Secure Campus Portal ({settings.APP_ENV} mode)...")
    print(f"[*] Access URL: http://127.0.0.1:8000")
    print(f"[*] Documentation: http://127.0.0.1:8000/docs")
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=(settings.APP_ENV == "development"),
        log_level="info",
    )
