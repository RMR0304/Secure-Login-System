"""
Authentication and Login Security Tests
=======================================
Covers:
- TC-01: Correct password -> Login succeeds
- TC-02: Incorrect password -> Login rejected
- Non-existent account -> Generic authentication failure (anti-enumeration)
- TC-18: Malformed request -> Validation error
"""

import pytest
from app.models.user import User


@pytest.fixture
def registered_user(client):
    """Helper fixture to register a test student user."""
    payload = {
        "full_name": "Login Test User",
        "student_id": "LOG001",
        "email": "login_test@example.local",
        "password": "CorrectPassword!123",
        "confirm_password": "CorrectPassword!123",
    }
    resp = client.post("/api/auth/register", json=payload)
    assert resp.status_code == 201
    return payload


def test_tc01_correct_password_login_succeeds(client, registered_user, db):
    """
    TC-01: Providing correct registered credentials succeeds.
    Sets HttpOnly session cookie, updates last_login_at, resets failed attempts.
    """
    resp = client.post(
        "/api/auth/login",
        json={
            "email": registered_user["email"],
            "password": registered_user["password"],
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["message"] == "Authentication successful."
    assert data["user"]["email"] == registered_user["email"]

    # Verify session cookie is set
    assert "campus_session" in resp.cookies
    cookie = resp.cookies["campus_session"]
    assert len(cookie) > 20

    # Verify database state
    user = db.query(User).filter(User.email == registered_user["email"]).first()
    assert user.failed_login_attempts == 0
    assert user.last_login_at is not None


def test_tc02_incorrect_password_login_rejected(client, registered_user, db):
    """
    TC-02: Providing an incorrect password results in authentication rejection.
    Increments failed_login_attempts counter and returns a generic failure message.
    """
    resp = client.post(
        "/api/auth/login",
        json={
            "email": registered_user["email"],
            "password": "WrongPassword!999",
        },
    )
    assert resp.status_code == 401
    # Generic failure message: must not reveal whether password was wrong vs email non-existent
    assert "Authentication failed" in resp.json()["detail"]

    # Verify failed attempts counter incremented in database
    user = db.query(User).filter(User.email == registered_user["email"]).first()
    assert user.failed_login_attempts == 1


def test_nonexistent_user_login_rejected_with_generic_message(client):
    """
    Anti-Enumeration Test:
    Login attempt with unregistered email must return the IDENTICAL generic error message
    and 401 code as an incorrect password attempt.
    """
    resp = client.post(
        "/api/auth/login",
        json={
            "email": "ghost_nonexistent@example.local",
            "password": "SomePassword!123",
        },
    )
    assert resp.status_code == 401
    assert "Authentication failed" in resp.json()["detail"]


def test_tc18_malformed_login_request(client):
    """
    TC-18: Malformed request payload returns defensive validation error.
    """
    # Missing password field
    resp = client.post(
        "/api/auth/login",
        json={"email": "student@example.local"},
    )
    assert resp.status_code == 400
    assert "password" in resp.json()["detail"].lower()

    # Invalid JSON
    resp_bad_json = client.post(
        "/api/auth/login",
        content="not a json string",
        headers={"Content-Type": "application/json"},
    )
    assert resp_bad_json.status_code == 400
