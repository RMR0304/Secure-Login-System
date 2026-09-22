"""
Database Initialization Script
==============================
Initializes the SQLite local database schema and verifies table creation.
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import engine, Base
from app.models import User, PasswordHistory, SessionModel, RecoveryToken, SecurityEvent
from app.config import get_settings


def init_database():
    """Create all required tables in SQLite."""
    settings = get_settings()
    print(f"[*] Initializing Secure Campus Portal database...")
    print(f"[*] Target DB URL: {settings.DATABASE_URL}")

    # Ensure data directory exists
    os.makedirs("./data", exist_ok=True)

    # Create schema
    Base.metadata.create_all(bind=engine)

    print("[+] Database tables initialized successfully:")
    for table_name in Base.metadata.tables.keys():
        print(f"    - {table_name}")
    print("[+] Ready for use.")


if __name__ == "__main__":
    init_database()
