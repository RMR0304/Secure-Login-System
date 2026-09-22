"""
Account Lockout Security Tests
==============================
Covers:
- TC-05: Repeated failures -> Account locked
- Maximum 5 consecutive failed login attempts trigger temporary lockout
- Attempting correct credentials during active lockout is rejected (HTTP 423)
- Lockout expiration automatically restores authentication capability
"""

from datetime import datetime, timedelta, timezone
from app.models.user import User


def test_tc05_repeated_failures_trigger_account_lockout(client, db):
    """
    TC-05:
    1. Register user with correct password.
    2. Submit 4 incorrect passwords (each returns 401).
    3. Submit 5th incorrect password (reaches MAX_FAILED_ATTEMPTS = 5).
       Account must become LOCKED, returning HTTP 423.
    4. Submit CORRECT password while locked -> Must be REJECTED (HTTP 423).
    5. Simulate lockout expiration -> Authentication succeeds.
    """
    email = "lockout_victim@example.local"
    correct_pwd = "VictimPassword!123"

    # 1. Register student
    reg_resp = client.post(
        "/api/auth/register",
        json={
            "full_name": "Lockout Victim",
            "student_id": "LCK001",
            "email": email,
            "password": correct_pwd,
            "confirm_password": correct_pwd,
        },
    )
    assert reg_resp.status_code == 201

    # 2. Submit 4 failed attempts
    for attempt in range(1, 5):
        resp = client.post(
            "/api/auth/login",
            json={"email": email, "password": f"WrongAttempt{attempt}!123"},
        )
        assert resp.status_code == 401, f"Attempt {attempt} should return 401"
        assert "Authentication failed" in resp.json()["detail"]

    # Check database state: failed_login_attempts should be 4, locked_until should be None
    user = db.query(User).filter(User.email == email).first()
    assert user.failed_login_attempts == 4
    assert user.locked_until is None

    # 3. Submit 5th failed attempt (Threshold reached)
    resp_5 = client.post(
        "/api/auth/login",
        json={"email": email, "password": "WrongAttempt5!123"},
    )
    assert resp_5.status_code == 423
    assert "locked" in resp_5.json()["detail"].lower()

    # Check database state: failed_login_attempts is 5, locked_until is set in future
    db.refresh(user)
    assert user.failed_login_attempts == 5
    assert user.locked_until is not None
    assert user.is_locked() is True

    # 4. Attempt login with CORRECT password while account is locked
    resp_correct_while_locked = client.post(
        "/api/auth/login",
        json={"email": email, "password": correct_pwd},
    )
    assert resp_correct_while_locked.status_code == 423
    assert "locked" in resp_correct_while_locked.json()["detail"].lower()

    # 5. Simulate passage of lockout duration (15 minutes into the past)
    user.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()

    # 6. Attempt login now that lockout has expired
    resp_after_expiry = client.post(
        "/api/auth/login",
        json={"email": email, "password": correct_pwd},
    )
    assert resp_after_expiry.status_code == 200
    assert resp_after_expiry.json()["message"] == "Authentication successful."

    # Failed attempts counter must be reset
    db.refresh(user)
    assert user.failed_login_attempts == 0
    assert user.locked_until is None
