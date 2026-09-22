"""
Synthetic Test User Seeding Script
==================================
Creates baseline synthetic student accounts for academic evaluation.
Demonstrates that two users registered with identical passwords receive
completely distinct Argon2id hashes due to unique per-user salts.
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.database import SessionLocal
from app.models.user import User
from app.schemas.auth import UserRegisterRequest
from app.services.auth_service import AuthService

DEMO_PASSWORD = "CampusPassword!123"

SAMPLE_STUDENTS = [
    {
        "full_name": "Alice Smith",
        "student_id": "STU1001",
        "email": "alice@example.local",
        "password": DEMO_PASSWORD,
    },
    {
        "full_name": "Bob Johnson",
        "student_id": "STU1002",
        "email": "bob@example.local",
        "password": DEMO_PASSWORD,
    },
]


def seed_test_users():
    """Populate synthetic student data safely."""
    db = SessionLocal()
    auth_service = AuthService()

    print("[*] Seeding synthetic assessment test accounts...")

    for data in SAMPLE_STUDENTS:
        existing = db.query(User).filter(User.email == data["email"]).first()
        if existing:
            print(f"[-] User '{data['email']}' already exists. Skipping.")
            continue

        req = UserRegisterRequest(
            full_name=data["full_name"],
            student_id=data["student_id"],
            email=data["email"],
            password=data["password"],
            confirm_password=data["password"],
        )

        success, user, msg = auth_service.register_user(db, req, ip_address="127.0.0.1", user_agent="SeedScript/1.0")
        if success:
            print(f"[+] Created synthetic student: {user.full_name} ({user.email}) [ID: {user.student_id}]")
            print(f"    Argon2id Hash: {user.password_hash[:35]}...[TRUNCATED]")
        else:
            print(f"[!] Failed to create {data['email']}: {msg}")

    db.close()
    print("[+] Test user seeding complete.")


if __name__ == "__main__":
    seed_test_users()
