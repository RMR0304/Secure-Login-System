# Secure Campus Portal &mdash; Secure Password Storage

> **HCLTech Cybersecurity Practical Assessment: Project 1**  
> *Scenario:* "A campus portal must protect student credentials even if its account database is copied or exposed."

---

## 1. Project Overview & Problem Statement
In an academic campus environment, user databases frequently store credentials for thousands of students and faculty members. If an adversary gains unauthorized access to the database (via SQL injection, insider threat, or unencrypted backup leakage), storing credentials in plaintext or with reversible ciphers leads to catastrophic credential compromise and widespread account takeover.

This project delivers a complete, production-grade local campus authentication system implementing **Argon2id password hashing**, **per-user dynamic cryptographic salts**, **last-three password history enforcement**, **automated account lockout**, and **anti-enumeration defensive security controls**.

---

## 2. Real-World Context & Industry Importance
1. **Credential Stuffing & Dictionary Attacks:** Attackers routinely utilize precomputed rainbow tables and automated botnets to crack unsalted or weak hashes (MD5, SHA-1, single-iteration SHA-256).
2. **NIST SP 800-63B & OWASP Digital Identity Compliance:** Modern standards mandate memory-hard password derivation functions, length-based complexity policies, and strict defense against credential reuse.
3. **Defense-in-Depth:** Password storage is engineered under the assumption of breach: even if the raw database is leaked publicly, the computational cost of cracking the Argon2id hashes renders offline dictionary attacks infeasible.

---

## 3. Learning Objectives
- Master modern key derivation functions (KDFs) and understand why password hashing differs fundamentally from encryption.
- Implement per-user dynamic salts to neutralize rainbow tables and prevent cross-account hash correlation.
- Build automated brute-force defenses via account lockout and constant-time password verification.
- Enforce strict password policies and FIFO-based historical password reuse restrictions.
- Conduct automated positive and negative security testing using `pytest` and `httpx`.

---

## 4. Logical System Architecture

```
                    USER BROWSER (HTML5 / Vanilla JS)
                                  │
                                  ▼ [HTTP / HttpOnly Secure Cookies]
                   WEB APPLICATION (FastAPI Gateway)
                                  │
                                  ▼ [Dependency Injection & Validation]
               AUTHENTICATION SERVICE (Lockout / Policies)
                                  │
                     ┌────────────┴────────────┐
                     ▼                         ▼
             ARGON2ID SERVICE          SQLITE LOCAL DATABASE
          (RFC 9106 Derivation)       (PRAGMA foreign_keys=ON)
```

For detailed architectural sequence and component diagrams, consult [`docs/architecture.md`](file:///c:/Users/ASUS/OneDrive/Desktop/Coding/CyberSecurity/secure-password-storage/docs/architecture.md).

---

## 5. Technology Stack

| Layer | Technology | Rationale |
| :--- | :--- | :--- |
| **Backend Framework** | Python 3.11+ / FastAPI | High-performance asynchronous API, native type safety, OpenAPI documentation. |
| **Server Engine** | Uvicorn (ASGI) | Production-ready lightweight asynchronous server. |
| **Database ORM** | SQLite & SQLAlchemy 2.0 | Zero-configuration local SQL database with strict foreign key constraints enabled. |
| **Password Derivation** | Argon2id (`argon2-cffi`) | Winner of Password Hashing Competition; memory-hard, side-channel resistant. |
| **Validation & Config** | Pydantic v2 & Pydantic Settings | Strict type enforcement, input sanitization, environment variable loading. |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript | Responsive cybersecurity-themed interface; zero external framework dependencies. |
| **Testing Suite** | Pytest, FastAPI TestClient | 20 automated unit, integration, and security negative test cases. |

---

## 6. Directory Structure

```
secure-password-storage/
├── app/
│   ├── __init__.py
│   ├── main.py                  # Application entry, middleware, exception handlers
│   ├── config.py                # Pydantic Settings (.env configuration loader)
│   ├── database.py              # SQLite engine, session maker, foreign key pragma
│   ├── models/                  # SQLAlchemy ORM entities
│   │   ├── __init__.py
│   │   ├── user.py              # Student accounts & lockout tracking
│   │   ├── password_history.py  # Last-3 historical password hashes
│   │   ├── session.py           # Server-side hashed sessions
│   │   ├── recovery_token.py    # Time-bounded single-use reset tokens
│   │   └── security_event.py    # Zero-leakage audit trail
│   ├── schemas/                 # Pydantic request/response schemas
│   │   ├── __init__.py
│   │   ├── auth.py              # Registration, login, user models
│   │   ├── password.py          # Change password & policy validation
│   │   └── recovery.py          # Account recovery payloads
│   ├── services/                # Business logic & cryptographic primitives
│   │   ├── __init__.py
│   │   ├── password_service.py  # Argon2id hashing, verification, policy checks
│   │   ├── auth_service.py      # Registration, login, lockout orchestration
│   │   ├── session_service.py   # Cookie issuance & SHA-256 session indexing
│   │   ├── recovery_service.py  # Reset tokens & single-use consumption
│   │   └── audit_service.py     # Sanitized audit logging
│   ├── routers/                 # FastAPI routes
│   │   ├── __init__.py
│   │   ├── auth.py              # /api/auth/register, login, logout, GET /login
│   │   ├── users.py             # /dashboard, /api/me
│   │   ├── password.py          # /change-password, /api/auth/change-password
│   │   └── recovery.py          # /recover, /api/auth/recovery/*
│   ├── middleware/
│   │   ├── __init__.py
│   │   └── security.py          # Security headers & session authentication
│   ├── templates/               # Jinja2 HTML templates
│   │   ├── base.html            # Dark cybersecurity base layout
│   │   ├── login.html           # Login view with lockout indicator
│   │   ├── register.html        # Registration with live policy checklist
│   │   ├── dashboard.html       # Student profile & audit log view
│   │   ├── change_password.html # Password update with history warning
│   │   ├── recovery.html        # Two-step account recovery interface
│   │   └── error.html           # Sanitized error page
│   └── static/
│       ├── css/style.css        # Premium dark cybersecurity styling
│       └── js/app.js            # Client-side validation & async auth
├── tests/                       # Automated test suite
│   ├── __init__.py
│   ├── conftest.py              # Test database & client fixtures
│   ├── test_registration.py     # TC-03, TC-06, TC-07, TC-08, TC-09, plaintext absence
│   ├── test_login.py            # TC-01, TC-02, TC-18, anti-enumeration
│   ├── test_password_history.py # TC-04, TC-11, TC-12, TC-13 (FIFO last-3 history)
│   ├── test_lockout.py          # TC-05 (5 failed attempts lock, auto-recovery)
│   ├── test_recovery.py         # TC-16, TC-17 (token expiration & single-use)
│   ├── test_sessions.py         # TC-10, TC-14, TC-15 (protected routes & logout)
│   └── test_security.py         # TC-19, TC-20 (audit privacy & secret validation)
├── scripts/
│   ├── init_db.py               # Table creation & schema verification
│   ├── create_test_user.py      # Seeds synthetic student accounts
│   └── inspect_db.py            # Masked database evidence reporter
├── data/                        # SQLite storage directory
│   └── .gitkeep
├── docs/                        # Assessment documentation
│   ├── architecture.md          # Architecture & Mermaid sequence diagrams
│   ├── security.md              # Cryptographic justifications & threat model
│   ├── api.md                   # REST API specification
│   └── testing.md               # 8-column verification matrix (TC-01 to TC-20)
├── screenshots/                 # Assessment evidence folder
│   └── .gitkeep
├── .env.example                 # Configuration template
├── .gitignore                   # Ignores databases and secrets
├── requirements.txt             # Pinned Python dependencies
├── run.py                       # Application execution script
└── README.md                    # Main project documentation
```

---

## 7. Database Schema & Tables

1. **`users`**: Contains student IDs, emails, Argon2id password hashes, failed login counters, and lockout timestamps.
2. **`password_history`**: Tracks up to 3 prior Argon2id password hashes per user.
3. **`sessions`**: Stores SHA-256 hashes of issued session tokens with expiration and revocation timestamps.
4. **`recovery_tokens`**: Stores SHA-256 hashes of temporary single-use reset tokens.
5. **`security_events`**: Stores sanitized audit logs of authentication operations without credentials.

---

## 8. Cryptographic Password Hashing (Argon2id)
The portal uses **Argon2id** (RFC 9106) configured via `argon2-cffi`:
- **Algorithm Identifier:** `$argon2id$v=19$`
- **Memory Cost ($m$):** 65,536 KiB (64 MiB)
- **Time Cost ($t$):** 2 passes over memory
- **Parallelism ($p$):** 2 threads/lanes
- **Salt Length:** 16 bytes (128 bits) generated via OS CSPRNG per password.

Each stored hash takes the standardized PHC string format:
`$argon2id$v=19$m=65536,t=2,p=2$<16-byte-salt>$<32-byte-hash>`

---

## 9. Dynamic Salts & Rainbow Table Resistance
- Every password hash receives a unique random 16-byte salt automatically generated by `argon2-cffi`.
- Static/shared salts are strictly prohibited.
- **Hash Uniqueness:** Even if Alice and Bob register with the exact same password (`CampusPassword!123`), their stored hashes in the database will be completely different, defeating precomputed rainbow table attacks.

---

## 10. Last-Three Password History Enforcement
- The system stores only cryptographic hashes in `password_history`.
- When a user changes their password:
  1. The new password is validated against the active password hash.
  2. The new password is verified against the last 3 historical hashes using constant-time Argon2 verification.
  3. If matched, the change is rejected.
  4. Once a new password is accepted, the current hash moves to history, and entries beyond 3 are pruned (FIFO queue).

---

## 11. Account Lockout Protection
- **Max Consecutive Failures:** 5 attempts.
- **Lockout Duration:** 15 minutes (configurable via `.env`).
- When an account is locked, even submitting the correct password returns `HTTP 423 Locked`.
- Once the 15-minute window elapses, the next valid login automatically resets the failed counter.

---

## 12. Account Recovery Flow
- Self-service recovery issues a 256-bit cryptographically random token.
- Only the **SHA-256 digest** is stored in the database.
- Tokens expire after 10 minutes and can only be consumed once (`used_at` timestamp).
- For local demonstration and academic grading, the generated token is displayed directly in a **DEVELOPMENT / LOCAL TESTING ONLY** banner.

---

## 13. Secure Session Management
- Sessions are tracked server-side in the `sessions` table.
- Raw tokens are stored client-side inside an `HttpOnly`, `SameSite=Lax` cookie.
- The server stores only the **SHA-256 digest** of the session token.
- Logging out revokes the session in the database immediately.

---

## 14. Defensive Security Controls Summary
1. **Argon2id Hashing:** RFC 9106 memory-hard protection against GPU brute force.
2. **Dynamic 16-byte Salts:** Defeats rainbow tables and hash correlation.
3. **Password Policy Enforcement:** Min 12 chars, upper, lower, numbers, symbols, no personal identifiers.
4. **Last-3 Password History:** Prevents credential cycling.
5. **5-Attempt Account Lockout:** Mitigates automated credential stuffing.
6. **Generic Error Responses:** Prevents username/email harvesting.
7. **HttpOnly & SameSite Cookies:** Mitigates XSS cookie theft and CSRF.
8. **Server-Side Session Hashing:** Database leakage does not expose active session tokens.
9. **Zero Credential Logging:** Passwords and tokens are strictly excluded from logs.
10. **Sanitized Error Handling:** Prevents stack traces and SQL disclosure.

---

## 15. Installation & Setup Guide

### 15.1 Prerequisites
- Python 3.11 or higher
- Windows PowerShell or CMD

### 15.2 Step-by-Step Installation Commands

```powershell
# 1. Navigate to the project root directory
cd secure-password-storage

# 2. Create Python virtual environment
python -m venv .venv

# 3. Activate the virtual environment
.venv\Scripts\activate

# 4. Install pinned dependencies
pip install -r requirements.txt

# 5. Initialize environment variables
copy .env.example .env

# 6. Initialize the SQLite local database
python scripts/init_db.py

# 7. Seed baseline synthetic student test accounts
python scripts/create_test_user.py

# 8. Start the FastAPI development server
python run.py
```

Open your browser at: **`http://127.0.0.1:8000`**

---

## 16. Running Automated Tests

Run the full pytest suite with verbose output:

```powershell
pytest -v
```

All 20 test cases will execute against an isolated in-memory SQLite database.

---

## 17. Inspecting Database Evidence (TC-03 & Password Privacy)

Execute the database inspection utility to generate masked evidence showing that passwords are never stored in plaintext:

```powershell
python scripts/inspect_db.py
```

**Expected Masked Output:**
```
Record #1:
  User Email:       alice@example.local
  Student ID:       STU1001
  Plaintext Pwd:    [NOT STORED]
  Password Hash:    $argon2id$v=19$m=65536,t=2,p=2$[SALT_MASKED]$[DIGEST_MASKED]
  Failed Attempts:  0
  Account Status:   ACTIVE
```

---

## 18. Mandatory HCLTech Test Cases

| Test Case | Scenario | Expected Result | Automated Test |
| :--- | :--- | :--- | :--- |
| **TC-01** | Correct password | Login succeeds, session cookie set. | `test_tc01_correct_password_login_succeeds` |
| **TC-02** | Incorrect password | Login rejected (401), failed attempts incremented. | `test_tc02_incorrect_password_login_rejected` |
| **TC-03** | Same password, two users | Stored Argon2id hashes differ due to unique salts. | `test_tc03_same_password_two_users_different_hashes` |
| **TC-04** | Reuse old password | Change rejected (400) because it matches history. | `test_tc04_and_tc13_password_history_last_three_enforcement` |
| **TC-05** | Repeated failures | Account locked after 5 consecutive failures (423). | `test_tc05_repeated_failures_trigger_account_lockout` |

