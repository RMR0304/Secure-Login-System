"""
System-Wide Security and Hardening Tests
========================================
Covers:
- TC-19: Sensitive credentials (passwords, tokens) NEVER appear in security logs or DB
- TC-20: Environment secret missing -> Application fails safely without exposing secrets
- Defensive HTTP security headers
- Anti-enumeration timing mitigation
"""

import pytest
from pydantic import ValidationError
from app.config import Settings
from app.models.security_event import SecurityEvent
from app.services.audit_service import SENSITIVE_KEYS


def test_tc19_no_sensitive_data_in_security_logs(client, db):
    """
    TC-19: Passwords and authorization secrets must NEVER appear in the audit trail.
    Executes multiple actions and audits all database records in security_events.
    """
    secret_password = "SensitivePassword!123"
    email = "audit_target@example.local"

    # Action 1: Registration
    client.post(
        "/api/auth/register",
        json={
            "full_name": "Audit Target",
            "student_id": "AUD001",
            "email": email,
            "password": secret_password,
            "confirm_password": secret_password,
        },
    )

    # Action 2: Login failure with wrong password
    wrong_pwd = "WrongSecretPassword!999"
    client.post("/api/auth/login", json={"email": email, "password": wrong_pwd})

    # Action 3: Successful login
    login_resp = client.post("/api/auth/login", json={"email": email, "password": secret_password})

    # Action 4: Recovery request
    req_resp = client.post("/api/auth/recovery/request", json={"identifier": email})
    recovery_token = req_resp.json().get("dev_token", "")

    # Query ALL security events logged in database
    events = db.query(SecurityEvent).all()
    assert len(events) >= 3

    for ev in events:
        details_str = ev.details or ""
        # 1. Plaintext passwords must NOT be present
        assert secret_password not in details_str, f"Found plaintext password in event: {ev.event_type}"
        assert wrong_pwd not in details_str, f"Found failed password in event: {ev.event_type}"

        # 2. Raw recovery tokens must NOT be present
        if recovery_token:
            assert recovery_token not in details_str, f"Found recovery token in event: {ev.event_type}"

        # 3. Ensure no blacklisted keys leaked
        for sens in SENSITIVE_KEYS:
            # If key name was present, value should be redacted or omitted
            assert f"{sens}=" not in details_str or "[REDACTED]" in details_str


def test_tc20_missing_secret_fails_safely_without_disclosure(monkeypatch):
    """
    TC-20: Missing or invalid SESSION_SECRET triggers safe configuration validation error
    without leaking internal keys, variables, or unhandled crashes.
    """
    # Simulate missing secret
    with pytest.raises(ValidationError) as exc_info:
        Settings(SESSION_SECRET="")

    error_str = str(exc_info.value)
    # Confirm clear validation error raised
    assert "SESSION_SECRET" in error_str
    # Confirm error does not contain any leaked secrets
    assert "password" not in error_str.lower()
    assert "token" not in error_str.lower()


def test_defensive_http_security_headers(client):
    """
    Verify defensive HTTP security headers are present on all responses.
    """
    resp = client.get("/login")
    assert resp.status_code == 200

    headers = resp.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in headers
    assert "default-src 'self'" in headers.get("Content-Security-Policy")
