"""
Registration and Password Derivation Security Tests
===================================================
Covers:
- TC-03: Same password, two users -> Stored hashes differ (Unique Salt Test)
- TC-06: Weak password during registration -> Rejected
- TC-07: Password and confirmation mismatch -> Rejected
- TC-08: Duplicate email -> Rejected
- TC-09: Duplicate student ID -> Rejected
- Verification that plaintext passwords are NEVER persisted to the database.
"""

import pytest
from app.models.user import User
from app.services.password_service import PasswordService


def test_tc03_same_password_two_users_different_hashes(client, db):
    """
    TC-03: Same password used by two users must yield different stored hashes
    due to dynamically generated cryptographically secure random salts.
    """
    shared_password = "SecureCampusPassword!123"

    # Register User A
    resp_a = client.post(
        "/api/auth/register",
        json={
            "full_name": "Student A",
            "student_id": "STU001",
            "email": "studentA@example.local",
            "password": shared_password,
            "confirm_password": shared_password,
        },
    )
    assert resp_a.status_code == 201

    # Register User B with identical password
    resp_b = client.post(
        "/api/auth/register",
        json={
            "full_name": "Student B",
            "student_id": "STU002",
            "email": "studentB@example.local",
            "password": shared_password,
            "confirm_password": shared_password,
        },
    )
    assert resp_b.status_code == 201

    # Inspect database records directly
    user_a = db.query(User).filter(User.student_id == "STU001").first()
    user_b = db.query(User).filter(User.student_id == "STU002").first()

    assert user_a is not None
    assert user_b is not None

    # CRITICAL: Both users have the exact same password, but their hashes MUST differ
    assert user_a.password_hash != user_b.password_hash

    # Confirm Argon2id algorithm format
    assert user_a.password_hash.startswith("$argon2id$")
    assert user_b.password_hash.startswith("$argon2id$")

    # Confirm both verify successfully with their respective stored hash
    pwd_service = PasswordService()
    assert pwd_service.verify_password(user_a.password_hash, shared_password) is True
    assert pwd_service.verify_password(user_b.password_hash, shared_password) is True


def test_tc06_weak_password_registration_rejected(client):
    """
    TC-06: Weak passwords failing policy requirements must be rejected.
    """
    weak_passwords = [
        ("short", "Short!1a"),                         # < 12 characters
        ("no_upper", "alllowercase123!"),             # No uppercase
        ("no_lower", "ALLLOWERCASE123!"),             # No lowercase
        ("no_number", "NoNumbersInHere!@#"),          # No numbers
        ("no_special", "NoSpecialChars1234"),         # No special character
        ("contains_email", "alice@example.local123!"), # Contains email
        ("contains_sid", "STU1001_Secret!123"),       # Contains student ID
    ]

    for label, weak_pwd in weak_passwords:
        resp = client.post(
            "/api/auth/register",
            json={
                "full_name": "Weak Pwd Test",
                "student_id": "STU1001",
                "email": "alice@example.local",
                "password": weak_pwd,
                "confirm_password": weak_pwd,
            },
        )
        assert resp.status_code == 400, f"Expected rejection for {label}, got {resp.status_code}: {resp.text}"


def test_tc07_password_confirmation_mismatch_rejected(client):
    """
    TC-07: Mismatch between password and confirm_password must be rejected.
    """
    resp = client.post(
        "/api/auth/register",
        json={
            "full_name": "Mismatch Test",
            "student_id": "STU3001",
            "email": "mismatch@example.local",
            "password": "ValidPassword!123",
            "confirm_password": "DifferentPassword!123",
        },
    )
    assert resp.status_code == 400
    assert "match" in resp.json()["detail"].lower()


def test_tc08_duplicate_email_rejected(client):
    """
    TC-08: Attempting to register with an existing email must return 409 Conflict.
    """
    payload = {
        "full_name": "Original User",
        "student_id": "STU4001",
        "email": "unique@example.local",
        "password": "ValidPassword!123",
        "confirm_password": "ValidPassword!123",
    }
    first_resp = client.post("/api/auth/register", json=payload)
    assert first_resp.status_code == 201

    # Second registration with same email
    payload_dup = payload.copy()
    payload_dup["student_id"] = "STU4002"  # different student ID, same email
    dup_resp = client.post("/api/auth/register", json=payload_dup)
    assert dup_resp.status_code == 409
    assert "email address already exists" in dup_resp.json()["detail"]


def test_tc09_duplicate_student_id_rejected(client):
    """
    TC-09: Attempting to register with an existing student ID must return 409 Conflict.
    """
    payload = {
        "full_name": "Original Student",
        "student_id": "STU5001",
        "email": "student1@example.local",
        "password": "ValidPassword!123",
        "confirm_password": "ValidPassword!123",
    }
    first_resp = client.post("/api/auth/register", json=payload)
    assert first_resp.status_code == 201

    payload_dup = payload.copy()
    payload_dup["email"] = "student2@example.local"  # different email, same student ID
    dup_resp = client.post("/api/auth/register", json=payload_dup)
    assert dup_resp.status_code == 409
    assert "student id already exists" in dup_resp.json()["detail"].lower()


def test_plaintext_password_absence_in_database(client, db):
    """
    Database Security Verification:
    Verify that plaintext passwords are NEVER written to the database.
    """
    raw_pwd = "SuperSecretPassword!123"
    resp = client.post(
        "/api/auth/register",
        json={
            "full_name": "Plaintext Check",
            "student_id": "STU9999",
            "email": "security_audit@example.local",
            "password": raw_pwd,
            "confirm_password": raw_pwd,
        },
    )
    assert resp.status_code == 201

    # Fetch user row directly
    user = db.query(User).filter(User.student_id == "STU9999").first()
    assert user is not None

    # 1. Plaintext password does not match stored hash
    assert user.password_hash != raw_pwd

    # 2. Raw password substring is not present anywhere in the stored hash
    assert raw_pwd not in user.password_hash

    # 3. Plaintext password cannot be derived reversibly without brute force
    assert user.password_hash.startswith("$argon2id$v=19$")
