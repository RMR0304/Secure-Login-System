"""
Account Recovery Security Tests
===============================
Covers:
- Full synthetic recovery workflow (request -> verify -> reset)
- TC-16: Expired recovery token -> Recovery rejected
- TC-17: Single-use enforcement: Token reuse -> Rejected
- Database verification: raw token is NEVER stored unhashed.
"""

from datetime import datetime, timedelta, timezone
from app.models.recovery_token import RecoveryToken
from app.models.user import User


def test_full_recovery_flow(client, db):
    """
    Test complete valid password recovery flow.
    """
    email = "recovery_student@example.local"
    old_pwd = "OldPassword!123"
    new_pwd = "NewResetPassword!123"

    # Register user
    client.post(
        "/api/auth/register",
        json={
            "full_name": "Recovery Student",
            "student_id": "REC001",
            "email": email,
            "password": old_pwd,
            "confirm_password": old_pwd,
        },
    )

    # 1. Initiate Recovery
    req_resp = client.post("/api/auth/recovery/request", json={"identifier": email})
    assert req_resp.status_code == 200
    token = req_resp.json()["dev_token"]
    assert token is not None

    # Verify raw token is NOT in database
    token_entry = db.query(RecoveryToken).first()
    assert token_entry is not None
    assert token_entry.token_hash != token
    assert token not in token_entry.token_hash
    assert len(token_entry.token_hash) == 64  # SHA-256 digest length

    # 2. Verify token endpoint
    verify_resp = client.post("/api/auth/recovery/verify", json={"token": token})
    assert verify_resp.status_code == 200
    assert verify_resp.json()["valid"] is True

    # 3. Reset Password
    reset_resp = client.post(
        "/api/auth/recovery/reset",
        json={
            "token": token,
            "new_password": new_pwd,
            "confirm_new_password": new_pwd,
        },
    )
    assert reset_resp.status_code == 200
    assert "successfully" in reset_resp.json()["message"].lower()

    # 4. Old password fails
    fail_old = client.post("/api/auth/login", json={"email": email, "password": old_pwd})
    assert fail_old.status_code == 401

    # 5. New password succeeds
    login_new = client.post("/api/auth/login", json={"email": email, "password": new_pwd})
    assert login_new.status_code == 200


def test_tc16_expired_recovery_token_rejected(client, db):
    """
    TC-16: Submitting an expired recovery token must be rejected.
    """
    email = "expired_rec@example.local"
    pwd = "ValidPassword!123"

    client.post(
        "/api/auth/register",
        json={
            "full_name": "Expired Test",
            "student_id": "EXP001",
            "email": email,
            "password": pwd,
            "confirm_password": pwd,
        },
    )

    req_resp = client.post("/api/auth/recovery/request", json={"identifier": email})
    token = req_resp.json()["dev_token"]

    # Manually expire the token in the database
    token_entry = db.query(RecoveryToken).first()
    token_entry.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()

    # Attempt to reset with expired token
    reset_resp = client.post(
        "/api/auth/recovery/reset",
        json={
            "token": token,
            "new_password": "BrandNewPassword!123",
            "confirm_new_password": "BrandNewPassword!123",
        },
    )
    assert reset_resp.status_code == 400
    assert "expired" in reset_resp.json()["detail"].lower()


def test_tc17_recovery_token_reuse_rejected(client):
    """
    TC-17: Single-use token enforcement.
    Attempting to reuse a recovery token after it was consumed once must be rejected.
    """
    email = "reuse_rec@example.local"
    pwd = "ValidPassword!123"

    client.post(
        "/api/auth/register",
        json={
            "full_name": "Reuse Test",
            "student_id": "REU001",
            "email": email,
            "password": pwd,
            "confirm_password": pwd,
        },
    )

    req_resp = client.post("/api/auth/recovery/request", json={"identifier": email})
    token = req_resp.json()["dev_token"]

    # First consumption: Should succeed
    first_reset = client.post(
        "/api/auth/recovery/reset",
        json={
            "token": token,
            "new_password": "ResetPasswordOne!123",
            "confirm_new_password": "ResetPasswordOne!123",
        },
    )
    assert first_reset.status_code == 200

    # Second consumption: Attempt to reuse the same token
    second_reset = client.post(
        "/api/auth/recovery/reset",
        json={
            "token": token,
            "new_password": "ResetPasswordTwo!123",
            "confirm_new_password": "ResetPasswordTwo!123",
        },
    )
    assert second_reset.status_code == 400
    assert "already been used" in second_reset.json()["detail"].lower()
