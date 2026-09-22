"""
Password History and Change Security Tests
==========================================
Covers:
- TC-04: Reuse old password -> Change rejected
- TC-11: Change password without authentication -> Rejected
- TC-12: Wrong current password during change -> Rejected
- TC-13: Password reused from history -> Rejected
- Exact FIFO maintenance of last-three password hashes.
- Verification that password_history contains ONLY cryptographic hashes.
"""

import pytest
from app.models.password_history import PasswordHistory
from app.models.user import User


@pytest.fixture
def auth_session(client):
    """Register and log in a student user, returning cookies for authenticated requests."""
    pwd = "InitialPassword!123"
    client.post(
        "/api/auth/register",
        json={
            "full_name": "History Test Student",
            "student_id": "HIST001",
            "email": "history@example.local",
            "password": pwd,
            "confirm_password": pwd,
        },
    )
    login_resp = client.post(
        "/api/auth/login",
        json={"email": "history@example.local", "password": pwd},
    )
    return {"cookies": login_resp.cookies, "current_password": pwd, "email": "history@example.local"}


def test_tc11_change_password_unauthenticated_rejected(client):
    """
    TC-11: Attempting to invoke change-password without active session cookie is rejected with 401.
    """
    resp = client.post(
        "/api/auth/change-password",
        json={
            "current_password": "OldPassword!123",
            "new_password": "NewPassword!123",
            "confirm_new_password": "NewPassword!123",
        },
    )
    assert resp.status_code == 401


def test_tc12_wrong_current_password_rejected(client, auth_session):
    """
    TC-12: Providing incorrect current password during change operation is rejected.
    """
    resp = client.post(
        "/api/auth/change-password",
        json={
            "current_password": "IncorrectCurrentPwd!999",
            "new_password": "BrandNewPassword!123",
            "confirm_new_password": "BrandNewPassword!123",
        },
        cookies=auth_session["cookies"],
    )
    assert resp.status_code == 400
    assert "Current password is incorrect" in resp.json()["detail"]


def test_tc04_and_tc13_password_history_last_three_enforcement(client, db):
    """
    TC-04 & TC-13:
    Sequence demonstrating last-three password history enforcement:
    1. Initial password:  PasswordA!123
    2. Change to:         PasswordB!123 (History: [A])
    3. Change to:         PasswordC!123 (History: [B, A])
    4. Change to:         PasswordD!123 (History: [C, B, A])
    5. Attempt PasswordA!123 -> REJECTED (matches historical hash in last 3)
    6. Change to:         PasswordE!123 (History: [D, C, B], A is pruned)
    7. Attempt PasswordA!123 -> SUCCEEDS (A is no longer in the last 3 history)
    """
    pwd_A = "PasswordAlpha!123"
    pwd_B = "PasswordBravo!123"
    pwd_C = "PasswordCharlie!123"
    pwd_D = "PasswordDelta!123"
    pwd_E = "PasswordEcho!123"

    # Step 1: Register with Password A
    reg_resp = client.post(
        "/api/auth/register",
        json={
            "full_name": "History Sequence Student",
            "student_id": "SEQ001",
            "email": "sequence@example.local",
            "password": pwd_A,
            "confirm_password": pwd_A,
        },
    )
    assert reg_resp.status_code == 201

    # Login with A
    login_a = client.post("/api/auth/login", json={"email": "sequence@example.local", "password": pwd_A})
    cookies_a = login_a.cookies

    # Step 2: Change A -> B
    resp_b = client.post(
        "/api/auth/change-password",
        json={"current_password": pwd_A, "new_password": pwd_B, "confirm_new_password": pwd_B},
        cookies=cookies_a,
    )
    assert resp_b.status_code == 200

    # Step 3: Login with B and Change B -> C
    login_b = client.post("/api/auth/login", json={"email": "sequence@example.local", "password": pwd_B})
    resp_c = client.post(
        "/api/auth/change-password",
        json={"current_password": pwd_B, "new_password": pwd_C, "confirm_new_password": pwd_C},
        cookies=login_b.cookies,
    )
    assert resp_c.status_code == 200

    # Step 4: Login with C and Change C -> D
    login_c = client.post("/api/auth/login", json={"email": "sequence@example.local", "password": pwd_C})
    resp_d = client.post(
        "/api/auth/change-password",
        json={"current_password": pwd_C, "new_password": pwd_D, "confirm_new_password": pwd_D},
        cookies=login_c.cookies,
    )
    assert resp_d.status_code == 200

    # Step 5: Login with D and Attempt to reuse Password A
    # Current: D, History contains: [C, B, A] -> Last 3 entries!
    login_d = client.post("/api/auth/login", json={"email": "sequence@example.local", "password": pwd_D})
    resp_reuse_a = client.post(
        "/api/auth/change-password",
        json={"current_password": pwd_D, "new_password": pwd_A, "confirm_new_password": pwd_A},
        cookies=login_d.cookies,
    )
    assert resp_reuse_a.status_code == 400
    assert "last 3 passwords" in resp_reuse_a.json()["detail"].lower()

    # Step 6: Change D -> E
    resp_e = client.post(
        "/api/auth/change-password",
        json={"current_password": pwd_D, "new_password": pwd_E, "confirm_new_password": pwd_E},
        cookies=login_d.cookies,
    )
    assert resp_e.status_code == 200

    # Verify history table in database contains exactly 3 entries (D, C, B) and all are Argon2 hashes
    user = db.query(User).filter(User.email == "sequence@example.local").first()
    history_records = db.query(PasswordHistory).filter(PasswordHistory.user_id == user.id).all()
    assert len(history_records) == 3
    for h in history_records:
        assert h.password_hash.startswith("$argon2id$")
        # Ensure no plaintext passwords in history
        assert pwd_A not in h.password_hash
        assert pwd_B not in h.password_hash

    # Step 7: Login with E and Now attempt to change to Password A
    # History is now: [D, C, B]. Password A is pruned and now allowed!
    login_e = client.post("/api/auth/login", json={"email": "sequence@example.local", "password": pwd_E})
    resp_allow_a = client.post(
        "/api/auth/change-password",
        json={"current_password": pwd_E, "new_password": pwd_A, "confirm_new_password": pwd_A},
        cookies=login_e.cookies,
    )
    assert resp_allow_a.status_code == 200
    assert "successfully" in resp_allow_a.json()["message"].lower()
