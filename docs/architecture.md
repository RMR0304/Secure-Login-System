# System Architecture & Technical Design

## 1. High-Level Architecture Overview

The **Secure Campus Portal** implements a defense-in-depth, 4-tier security architecture designed to preserve credential confidentiality even in the catastrophic event of a database compromise or account dumping attack.

```mermaid
flowchart LR
    subgraph Client Tier
        Browser["User Browser<br/>(HTML5 / CSS / Vanilla JS)"]
    end

    subgraph Presentation & Gateway Tier
        FastAPI["FastAPI Web Framework<br/>(Request Validation & Routing)"]
        SecHeaders["Security Middleware<br/>(CSP, HSTS, X-Frame, HttpOnly)"]
    end

    subgraph Service Tier
        AuthService["Authentication Service<br/>(Session & Lockout Management)"]
        PwdService["Password Service<br/>(Argon2id Hashing & Policies)"]
        RecService["Recovery Service<br/>(Single-Use Token Lifecycle)"]
        AuditService["Audit Service<br/>(Zero-Leakage Security Events)"]
    end

    subgraph Persistence Tier
        DB[("Local SQLite Database<br/>(PRAGMA foreign_keys=ON)")]
    end

    Browser -->|HTTP Requests / Secure Cookies| SecHeaders
    SecHeaders --> FastAPI
    FastAPI --> AuthService
    FastAPI --> RecService
    AuthService --> PwdService
    AuthService --> AuditService
    RecService --> PwdService
    RecService --> AuditService
    AuthService --> DB
    RecService --> DB
    AuditService --> DB
```

---

## 2. Component Structure

| Component | Technology | Primary Responsibilities |
| :--- | :--- | :--- |
| **User Interface** | HTML5, CSS3, Vanilla JavaScript | Responsive credential entry, live client-side policy evaluation, password toggle, dev recovery assistance. |
| **API Gateway & Routing** | FastAPI, Uvicorn | Request validation (Pydantic), cookie extraction, exception sanitization, static file serving. |
| **Security Middleware** | Starlette BaseHTTPMiddleware | Injects HTTP hardening headers (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`). |
| **Authentication Service** | Python 3 | Coordinates login validation, tracks consecutive failed attempts, enforces temporary lockout windows. |
| **Password Service** | `argon2-cffi` | Argon2id key derivation, 16-byte cryptographically secure random salt generation, constant-time verification, last-3 history check. |
| **Session Service** | Python `secrets`, `hashlib` | Generates 256-bit cryptographically secure session tokens, indexes SHA-256 digests in database, invalidates on logout. |
| **Recovery Service** | Python `secrets`, `hashlib` | Issues time-bounded, single-use reset tokens stored as SHA-256 hashes, handles reset validation. |
| **Audit Service** | Python Logging & SQLAlchemy | Records immutable security events (`LOGIN_FAILURE`, `ACCOUNT_LOCKED`, etc.) while redacting credentials. |
| **Local Database** | SQLite, SQLAlchemy ORM | Enforces foreign keys, unique constraints, and indexes without storing plaintext secrets. |

---

## 3. Sequence Diagrams

### 3.1 User Registration Flow (TC-01, TC-03, TC-06 to TC-09)

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Browser
    participant Gateway as FastAPI Router
    participant Auth as AuthService
    participant Pwd as PasswordService
    participant DB as SQLite DB

    User->>Browser: Fill Registration Form (Name, ID, Email, Password)
    Browser->>Browser: Live Client-Side Policy Validation
    Browser->>Gateway: POST /api/auth/register
    Gateway->>Gateway: Pydantic Schema & Match Validation
    Gateway->>Auth: register_user()
    Auth->>DB: Query existing Email or Student ID
    alt Duplicate Found
        DB-->>Auth: Record exists
        Auth-->>Gateway: HTTP 409 Conflict
        Gateway-->>Browser: Duplicate account error
    else Unique Record
        Auth->>Pwd: validate_password_policy()
        alt Policy Failed
            Pwd-->>Auth: Policy Violations
            Auth-->>Gateway: HTTP 400 Bad Request
            Gateway-->>Browser: Show missing requirements
        else Policy Passed
            Auth->>Pwd: hash_password(password)
            Note over Pwd: Generate 16-byte random salt<br/>Derive Argon2id hash (RFC 9106)
            Pwd-->>Auth: $argon2id$v=19$m=65536,t=2,p=2$<salt>$<digest>
            Auth->>DB: INSERT into users (hash, metadata)
            Auth->>DB: INSERT into security_events (REGISTRATION_SUCCESS)
            DB-->>Auth: Commit OK
            Auth-->>Gateway: Success (Sanitized User Object)
            Gateway-->>Browser: HTTP 201 Created
            Browser-->>User: Redirect to Sign In
        end
    end
```

### 3.2 Authentication & Account Lockout Flow (TC-01, TC-02, TC-05)

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Browser
    participant Gateway as FastAPI Router
    participant Auth as AuthService
    participant Pwd as PasswordService
    participant DB as SQLite DB

    User->>Browser: Submit Email & Password
    Browser->>Gateway: POST /api/auth/login
    Gateway->>Auth: authenticate_user(email, password)
    Auth->>DB: SELECT * FROM users WHERE email = ?

    alt User Not Found
        Note over Auth,Pwd: Perform dummy Argon2 verification<br/>to prevent timing enumeration
        Auth->>Pwd: verify_password(DUMMY_HASH, password)
        Auth->>DB: INSERT security_event (LOGIN_FAILURE)
        Auth-->>Gateway: HTTP 401 "Authentication failed"
    else User Found
        alt Account Currently Locked (locked_until > now)
            Auth->>DB: INSERT security_event (ACCOUNT_LOCKED attempt)
            Auth-->>Gateway: HTTP 423 Locked
            Gateway-->>Browser: Temporary Lockout Alert
        else Account Active or Lockout Expired
            Auth->>Pwd: verify_password(stored_hash, password)
            alt Password Incorrect
                Note over Auth: Increment failed_login_attempts
                alt failed_attempts >= 5
                    Note over Auth: Set locked_until = now + 15 min
                    Auth->>DB: UPDATE users SET failed_attempts=5, locked_until=...
                    Auth->>DB: INSERT security_event (ACCOUNT_LOCKED)
                    Auth-->>Gateway: HTTP 423 Locked
                else failed_attempts < 5
                    Auth->>DB: UPDATE users SET failed_attempts += 1
                    Auth->>DB: INSERT security_event (LOGIN_FAILURE)
                    Auth-->>Gateway: HTTP 401 "Authentication failed"
                end
            else Password Correct
                Note over Auth: Reset failed_attempts=0, locked_until=NULL
                Auth->>DB: UPDATE users SET failed_attempts=0, last_login_at=now
                Auth->>DB: INSERT security_event (LOGIN_SUCCESS)
                Auth->>DB: INSERT sessions (session_token_hash)
                Auth-->>Gateway: Success (raw_token)
                Gateway-->>Browser: Set-Cookie: campus_session (HttpOnly, SameSite=Lax)
                Gateway-->>Browser: HTTP 200 OK
                Browser-->>User: Redirect to /dashboard
            end
        end
    end
```

### 3.3 Password Change & History Flow (TC-04, TC-11 to TC-13)

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Browser
    participant Gateway as FastAPI Router
    participant Pwd as PasswordService
    participant DB as SQLite DB

    User->>Browser: Submit Current + New + Confirm Password
    Browser->>Gateway: POST /api/auth/change-password
    Gateway->>Gateway: Validate session cookie from DB
    alt Unauthenticated
        Gateway-->>Browser: HTTP 401 Unauthorized
    else Authenticated
        Gateway->>Pwd: verify_password(user.password_hash, current_password)
        alt Current Password Wrong
            Gateway-->>Browser: HTTP 400 "Current password is incorrect"
        else Current Password Valid
            Gateway->>Pwd: validate_password_policy(new_password)
            Gateway->>DB: SELECT password_hash FROM password_history (limit 3)
            Gateway->>Pwd: is_password_reused(new_pwd, current_hash, history_hashes)
            alt Reused from Current or Last 3
                Gateway-->>Browser: HTTP 400 "Matches current or last 3 passwords"
            else Fresh Unique Password
                Gateway->>DB: INSERT password_history (current_password_hash)
                Gateway->>DB: PRUNE password_history > 3 entries
                Gateway->>Pwd: hash_password(new_password)
                Gateway->>DB: UPDATE users SET password_hash = new_hash
                Gateway->>DB: UPDATE sessions SET revoked_at = now
                Gateway->>DB: INSERT security_event (PASSWORD_CHANGED)
                Gateway-->>Browser: HTTP 200 OK + Clear-Cookie
                Browser-->>User: Redirect to /login
            end
        end
    end
```

### 3.4 Account Recovery Flow (TC-16, TC-17)

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Browser
    participant Gateway as FastAPI Router
    participant Rec as RecoveryService
    participant DB as SQLite DB

    User->>Browser: Submit Email / Student ID
    Browser->>Gateway: POST /api/auth/recovery/request
    Gateway->>Rec: initiate_recovery(identifier)
    Rec->>DB: Look up user & invalidate prior unused tokens
    Note over Rec: Generate 256-bit token<br/>Store SHA-256(token) with 10m expiry
    Rec->>DB: INSERT recovery_tokens (token_hash, expires_at)
    Rec-->>Gateway: raw_token
    Gateway-->>Browser: Simulated Dev Presentation Banner
    User->>Browser: Submit Token + New Password
    Browser->>Gateway: POST /api/auth/recovery/reset
    Gateway->>Rec: reset_password(token, new_pwd)
    Rec->>DB: Query token by SHA-256(token)
    alt Token Missing / Expired / Already Used
        Rec-->>Gateway: HTTP 400 "Invalid or expired token"
    else Token Valid
        Rec->>DB: Verify history & update user.password_hash
        Rec->>DB: UPDATE recovery_tokens SET used_at = now
        Rec->>DB: Invalidate all existing sessions
        Rec->>DB: Reset failed_login_attempts & unlock account
        Rec-->>Gateway: HTTP 200 OK
        Gateway-->>Browser: Success & Redirect to Sign In
    end
```

---

## 4. Database Schema & Entity-Relationship Architecture

```mermaid
erDiagram
    USERS ||--o{ PASSWORD_HISTORY : "retains last 3"
    USERS ||--o{ SESSIONS : "tracks active"
    USERS ||--o{ RECOVERY_TOKENS : "issues temporary"
    USERS ||--o{ SECURITY_EVENTS : "logs audits"

    USERS {
        int id PK
        string student_id UK "Unique Student Code"
        string full_name "Student Full Name"
        string email UK "Institutional Email"
        string password_hash "Argon2id Hash String"
        int failed_login_attempts "Consecutive failure count"
        datetime locked_until "Lockout expiration window"
        boolean is_active "Account status flag"
        datetime created_at "Account creation UTC"
        datetime updated_at "Record update UTC"
        datetime last_login_at "Last authentication UTC"
    }

    PASSWORD_HISTORY {
        int id PK
        int user_id FK "References users.id ON DELETE CASCADE"
        string password_hash "Historical Argon2id Hash"
        datetime created_at "Timestamp of password retirement"
    }

    SESSIONS {
        int id PK
        int user_id FK "References users.id ON DELETE CASCADE"
        string session_token_hash UK "SHA-256 Digest of Cookie Token"
        datetime created_at "Session initialization UTC"
        datetime expires_at "Session expiration UTC"
        datetime revoked_at "Revocation timestamp UTC"
    }

    RECOVERY_TOKENS {
        int id PK
        int user_id FK "References users.id ON DELETE CASCADE"
        string token_hash UK "SHA-256 Digest of Single-Use Token"
        datetime created_at "Generation timestamp UTC"
        datetime expires_at "Token validity deadline (10 min)"
        datetime used_at "Consumption timestamp UTC"
    }

    SECURITY_EVENTS {
        int id PK
        int user_id FK "References users.id (nullable)"
        string event_type "Audit category tag"
        datetime event_time "Event occurrence UTC"
        string ip_address "Originating network address"
        string user_agent "Client browser agent"
        boolean success "Operation outcome"
        text details "Sanitized metadata (no secrets)"
    }
```
