# Campus Portal REST API Specification

This document details the interface contracts, authentication requirements, and security controls for all endpoints exposed by the Secure Campus Portal.

---

## 1. Authentication & Session Management

### 1.1 `POST /api/auth/register`
Creates a new student user account with Argon2id password derivation.

- **Authentication Required:** No
- **Headers:** `Content-Type: application/json`
- **Request Body:**
  ```json
  {
    "full_name": "Alice Smith",
    "student_id": "STU1001",
    "email": "alice@example.local",
    "password": "CampusPassword!123",
    "confirm_password": "CampusPassword!123"
  }
  ```
- **Responses:**
  - `201 Created`: Account successfully created. Returns sanitized user profile.
  - `400 Bad Request`: Validation failure (policy violation or confirmation mismatch).
  - `409 Conflict`: Email or Student ID is already registered.
- **Security Controls:**
  - Password hashed with Argon2id using a per-user 16-byte random salt.
  - Plaintext password is never stored or logged.

---

### 1.2 `POST /api/auth/login`
Authenticates a student and issues an HttpOnly session cookie.

- **Authentication Required:** No
- **Headers:** `Content-Type: application/json`
- **Request Body:**
  ```json
  {
    "email": "alice@example.local",
    "password": "CampusPassword!123"
  }
  ```
- **Responses:**
  - `200 OK`: Authentication succeeded.
    - Sets Cookie: `campus_session=<raw_token>; HttpOnly; SameSite=Lax; Path=/`
  - `401 Unauthorized`: Generic error message: `"Authentication failed. Invalid email or password."`
  - `423 Locked`: Consecutive failure threshold (5 attempts) reached. Account temporarily locked for 15 minutes.
- **Security Controls:**
  - Constant-time verification through `argon2-cffi`.
  - Non-existent accounts execute a dummy verification pass to prevent timing-based username enumeration.
  - Tracks failed attempts and enforces lockout.

---

### 1.3 `POST /api/auth/logout`
Revokes the caller's server-side session and removes authentication cookies.

- **Authentication Required:** Optional (no error if unauthenticated)
- **Headers:** Cookie containing `campus_session`
- **Responses:**
  - `200 OK`: `{"message": "Session successfully invalidated."}`
  - Sets-Cookie: `campus_session=; Max-Age=0`
- **Security Controls:**
  - Database record in `sessions` has `revoked_at` set immediately.

---

## 2. User & Profile Endpoints

### 2.1 `GET /api/me`
Retrieves public student profile details for the authenticated user.

- **Authentication Required:** Yes (`campus_session` cookie)
- **Responses:**
  - `200 OK`:
    ```json
    {
      "id": 1,
      "student_id": "STU1001",
      "full_name": "Alice Smith",
      "email": "alice@example.local",
      "is_active": true,
      "failed_login_attempts": 0,
      "locked_until": null,
      "created_at": "2026-09-22T08:00:00Z",
      "last_login_at": "2026-09-22T08:15:00Z"
    }
    ```
  - `401 Unauthorized`: Missing, invalid, or expired session.
  - `423 Locked`: Account is locked.

---

## 3. Password Lifecycle Endpoints

### 3.1 `POST /api/auth/change-password`
Updates the password of an authenticated user while strictly enforcing last-three history constraints.

- **Authentication Required:** Yes (`campus_session` cookie)
- **Headers:** `Content-Type: application/json`
- **Request Body:**
  ```json
  {
    "current_password": "CampusPassword!123",
    "new_password": "NewCampusPassword!456",
    "confirm_new_password": "NewCampusPassword!456"
  }
  ```
- **Responses:**
  - `200 OK`: Password updated. Clears active session cookie and forces fresh login.
  - `400 Bad Request`: Current password incorrect, policy failed, or password exists in last-3 history.
  - `401 Unauthorized`: Session expired or unauthenticated.
- **Security Controls:**
  - Historical comparison performed against Argon2id hashes in `password_history`.
  - Prior sessions are automatically invalidated upon password change.

---

### 3.2 `POST /api/auth/validate-policy`
Helper endpoint for live client-side password policy evaluation.

- **Authentication Required:** No
- **Request Body:**
  ```json
  {
    "password": "CandidatePassword!123",
    "email": "alice@example.local",
    "student_id": "STU1001"
  }
  ```
- **Responses:**
  - `200 OK`: `{"is_valid": true, "violations": []}`

---

## 4. Account Recovery Endpoints

### 4.1 `POST /api/auth/recovery/request`
Initiates self-service password recovery by generating a single-use authorization token.

- **Authentication Required:** No
- **Request Body:**
  ```json
  {
    "identifier": "alice@example.local"
  }
  ```
- **Responses:**
  - `200 OK`:
    - Development mode: Returns simulated token clearly labeled `DEVELOPMENT / LOCAL TESTING ONLY`.
    - Production mode: Returns generic success message.
- **Security Controls:**
  - Raw token is 256 bits of entropy. Only the SHA-256 hash is saved to SQLite.
  - Token validity window is capped at 10 minutes.

---

### 4.2 `POST /api/auth/recovery/verify`
Tests the validity of a candidate recovery token without consuming it.

- **Authentication Required:** No
- **Request Body:** `{"token": "..."}`
- **Responses:**
  - `200 OK`: `{"valid": true, "message": "Token is valid."}`
  - `400 Bad Request`: Token non-existent, expired, or already used.

---

### 4.3 `POST /api/auth/recovery/reset`
Consumes the single-use recovery token to reset the user's password and unlock the account.

- **Authentication Required:** No (Token-authorized)
- **Request Body:**
  ```json
  {
    "token": "...",
    "new_password": "BrandNewPassword!123",
    "confirm_new_password": "BrandNewPassword!123"
  }
  ```
- **Responses:**
  - `200 OK`: Password reset complete.
  - `400 Bad Request`: Token invalid, token reused, policy violation, or reused from last 3 passwords.
- **Security Controls:**
  - Sets `used_at = now()` preventing replay attacks (TC-17).
  - Unlocks account and clears `failed_login_attempts`.
  - Revokes all existing sessions.
