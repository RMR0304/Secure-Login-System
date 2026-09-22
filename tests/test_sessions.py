"""
Session Management and Authorization Tests
==========================================
Covers:
- TC-10: Access dashboard without authentication -> Redirected to /login
- TC-14: Logout -> Session invalidated and cookie cleared
- TC-15: Access dashboard after logout -> Access denied / redirected
- Verification that raw session tokens are NEVER stored in database.
- Expired session rejection.
"""

from datetime import datetime, timedelta, timezone
from app.models.session import SessionModel


def test_tc10_unauthorized_dashboard_access_redirects(client):
    """
    TC-10: Unauthenticated access to /dashboard is denied and redirects to /login.
    """
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers.get("location", "")

    # API route /api/me returns 401
    api_resp = client.get("/api/me")
    assert api_resp.status_code == 401


def test_tc14_and_tc15_logout_invalidates_session(client, db):
    """
    TC-14 & TC-15:
    1. Authenticate user -> Dashboard is accessible.
    2. Invoke logout -> Session is revoked in database, cookie cleared.
    3. Re-request dashboard with old cookie -> Access denied.
    """
    email = "session_user@example.local"
    pwd = "SessionPassword!123"

    client.post(
        "/api/auth/register",
        json={
            "full_name": "Session Student",
            "student_id": "SES001",
            "email": email,
            "password": pwd,
            "confirm_password": pwd,
        },
    )

    # 1. Log in
    login_resp = client.post("/api/auth/login", json={"email": email, "password": pwd})
    assert login_resp.status_code == 200
    cookies = login_resp.cookies
    raw_token = cookies["campus_session"]

    # Verify dashboard accessible with active cookie
    dash_resp = client.get("/dashboard", cookies=cookies)
    assert dash_resp.status_code == 200
    assert "Session Student" in dash_resp.text

    # Verify session token is hashed in database (not stored raw)
    db_session = db.query(SessionModel).first()
    assert db_session is not None
    assert db_session.session_token_hash != raw_token
    assert len(db_session.session_token_hash) == 64  # SHA-256
    assert db_session.revoked_at is None

    # 2. Logout (TC-14)
    logout_resp = client.post("/api/auth/logout", cookies=cookies)
    assert logout_resp.status_code == 200

    # Verify database session is revoked
    db.refresh(db_session)
    assert db_session.revoked_at is not None

    # 3. Access dashboard after logout using old cookie (TC-15)
    post_logout_resp = client.get("/dashboard", cookies=cookies, follow_redirects=False)
    assert post_logout_resp.status_code == 302
    assert "/login" in post_logout_resp.headers.get("location", "")

    # Protected API call with revoked token returns 401
    api_resp = client.get("/api/me", cookies=cookies)
    assert api_resp.status_code == 401


def test_expired_session_rejected(client, db):
    """
    Verify that sessions whose expiration timestamp has elapsed are rejected.
    """
    email = "expired_sess@example.local"
    pwd = "SessionPassword!123"

    client.post(
        "/api/auth/register",
        json={
            "full_name": "Expired Session User",
            "student_id": "SES002",
            "email": email,
            "password": pwd,
            "confirm_password": pwd,
        },
    )

    login_resp = client.post("/api/auth/login", json={"email": email, "password": pwd})
    cookies = login_resp.cookies

    # Force expiration in database
    db_session = db.query(SessionModel).filter(SessionModel.user_id.isnot(None)).first()
    db_session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()

    # Attempt API request with expired session
    api_resp = client.get("/api/me", cookies=cookies)
    assert api_resp.status_code == 401
