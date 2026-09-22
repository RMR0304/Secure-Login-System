# Comprehensive Security Analysis & Defensive Engineering

## 1. Cryptographic Fundamentals of Password Storage

### 1.1 Why Passwords Are Hashed (One-Way Transformation)
A password hash is a mathematical one-way function $H(P) = D$. It possesses the following mandatory properties:
1. **Pre-image Resistance:** Given digest $D$, it is computationally infeasible to find $P$ such that $H(P) = D$.
2. **Second Pre-image Resistance:** Given $P_1$, it is computationally infeasible to find $P_2 \neq P_1$ such that $H(P_1) = H(P_2)$.
3. **Collision Resistance:** It is computationally infeasible to find any pair $(P_1, P_2)$ such that $H(P_1) = H(P_2)$.

By storing only the cryptographic digest, the campus portal ensures that an adversary who gains unauthorized read access to the SQLite database file cannot read, extract, or reconstruct student plaintext passwords.

### 1.2 Hashing vs. Symmetric/Asymmetric Encryption
| Dimension | Cryptographic Hashing | Reversible Encryption (AES, RSA) |
| :--- | :--- | :--- |
| **Reversibility** | Irreversible by mathematical design. | Completely reversible with the decryption key. |
| **Key Dependency** | Does not require a secret decryption key to verify. | Relies entirely on the confidentiality of the secret key. |
| **Compromise Risk** | Database dump exposes only hashes. | Key compromise decrypts every user password instantly. |
| **Applicability** | Ideal for credential authentication. | Ideal for confidentiality of transmitted messages. |

Storing passwords with reversible encryption (such as AES-GCM or 3DES) violates foundational security engineering principles: any adversary with access to the source code, environment secrets, or memory can decrypt the entire student credential database.

---

## 2. Salt Strategy & Rainbow Table Neutralization

### 2.1 Why Salts Are Mandatory
A salt is a cryptographically random byte sequence $S$ concatenated with the password prior to derivation: $H(S \parallel P)$.

Without a salt, identical passwords yield identical hashes. An attacker can precompute hashes of billions of common passwords into a **lookup table** or **Rainbow Table**. With a precomputed table, inverting hashes requires $O(1)$ time complexity.

### 2.2 Why Unique Salts per User Are Required
If an application uses a static, shared salt across the entire database, precomputation is marginally harder, but an attacker can still compute a single rainbow table against that specific shared salt. Furthermore, two students with identical passwords would produce the identical stored hash, revealing credential commonality across accounts.

With a unique, cryptographically random 16-byte salt per user:
- Precomputed rainbow tables are rendered completely useless.
- Attackers must generate a new dictionary attack for every single user account independently.
- Two students registering with the identical password (e.g. `CampusPassword!123`) receive entirely distinct stored hashes (TC-03).

In this implementation, `argon2-cffi` automatically provisions a 128-bit (16-byte) CSPRNG salt per hash generation, serializing it into the standard PHC string format:
`$argon2id$v=19$m=65536,t=2,p=2$<16-byte-salt>$<32-byte-hash>`

---

## 3. Why Argon2id Was Chosen (RFC 9106)

Argon2 won the international Password Hashing Competition (PHC) in 2015 and is standardized under RFC 9106.

### 3.1 Variants Comparison
1. **Argon2d:** Data-dependent memory access. Extremely resistant to GPU cracking, but potentially vulnerable to side-channel cache-timing attacks.
2. **Argon2i:** Data-independent memory access. Highly resistant to side-channel attacks, but slightly more vulnerable to tradeoff GPU attacks.
3. **Argon2id (Used in this Project):** Hybrid approach. Uses Argon2i passes for the initial iteration to defeat side-channel cache attacks, then Argon2d passes to maximize memory-hardness against ASIC/GPU parallel brute-force adversaries.

### 3.2 Parameter Selection & Defense Rationale
```ini
ARGON2_TIME_COST=2       # 2 iterations across memory
ARGON2_MEMORY_COST=65536 # 64 MiB of RAM required per derivation
ARGON2_PARALLELISM=2    # 2 concurrent execution threads
```
- **Memory Hardness:** By requiring 64 MiB of RAM per hash evaluation, an attacker cannot deploy inexpensive high-throughput GPU/ASIC clusters (which rely on massive core counts with minuscule per-thread memory).
- **Time Hardness:** 2 passes introduce a deliberate computational delay (~40–80ms on standard CPUs), which is imperceptible to an interactive student logging in, but imposes an intolerable computational burden on offline brute-force crackers.

---

## 4. Policy, History, and Lockout Defense Controls

### 4.1 Password Complexity Policy
The policy enforces NIST SP 800-63B and OWASP guidelines:
- Minimum length of 12 characters exponentially expands the keyspace ($94^{12} \approx 4.7 \times 10^{23}$ combinations).
- Inclusion of uppercase, lowercase, numbers, and symbols prevents single-character-set dictionary traversal.
- Blacklisting student ID and email local-part prevents predictable, context-dependent passwords.

### 4.2 Last-Three Password History Enforcement
- Prevents immediate credential cycling where a student changes their password and immediately reverts back to their compromised password.
- Historical passwords are stored strictly as **Argon2id hashes** in `password_history`.
- When evaluating history, `argon2.PasswordHasher.verify()` is invoked in constant time against each of the last 3 stored hashes.
- Older hashes beyond the 3-entry threshold are automatically pruned via FIFO cleanup.

### 4.3 Account Lockout Mechanism
- **Threshold:** 5 consecutive failed login attempts.
- **Duration:** 15-minute temporary lockout window.
- **Defense Target:** Halts automated credential stuffing, distributed brute-force dictionary attacks, and password spraying.
- **Fail-Safe Recovery:** If an account is locked, students can either wait for the 15-minute duration to expire or utilize the out-of-band single-use account recovery workflow.
- **Anti-Enumeration Failure Response:** Authentication errors return generic messaging ("Authentication failed. Invalid email or password.") whether the account exists or not, preventing attackers from harvesting valid campus email addresses.

---

## 5. Session and Token Security

### 5.1 Server-Side Hashed Sessions
- Session identifiers are generated using Python's `secrets.token_urlsafe(32)` (256 bits of entropy).
- The raw token is sent to the client browser inside an **HttpOnly, SameSite=Lax** cookie.
- The server stores only the **SHA-256 cryptographic digest** of the token in the `sessions` table.
- Even if an intruder accesses the SQLite database, they obtain only one-way token hashes, preventing session hijacking.

### 5.2 Single-Use Recovery Tokens
- Recovery tokens are generated with 256 bits of CSPRNG entropy.
- Stored as SHA-256 hashes with an explicit 10-minute expiration window.
- Upon consumption, `used_at` is permanently set. Attempted re-use is immediately rejected (TC-17).
- Successful recovery invalidates all prior active sessions for that student.

---

## 6. Audit Logging & Leakage Prevention (TC-19)

- Passwords, confirmations, and raw tokens are strictly excluded from logging statements and persistent audit records.
- The `AuditService` implements an explicit sanitizer that checks for sensitive keys (`password`, `token`, `secret`) and replaces their values with `[REDACTED]`.
- Database table `security_events` tracks security operations (`LOGIN_FAILURE`, `ACCOUNT_LOCKED`, `PASSWORD_CHANGED`) with timestamps and client network identifiers for forensic auditing without storing authentication secrets.

---

## 7. Threat Modeling (STRIDE Matrix)

| Threat Category | Identified Threat | Mitigation Implemented |
| :--- | :--- | :--- |
| **Spoofing** | Adversary guesses credentials or steals session tokens. | Argon2id hashing, 5-attempt account lockout, HttpOnly session cookies with SHA-256 DB storage. |
| **Tampering** | Modification of session cookies or stored hashes. | Server-side session verification, foreign key constraints, constant-time hash verification. |
| **Repudiation** | User denies altering password or logging in. | Comprehensive `security_events` audit trail with UTC timestamps and IP records. |
| **Information Disclosure** | Credential dump from leaked SQLite database. | Passwords never stored in plaintext; per-user 16-byte random salts; masked database inspection tool. |
| **Denial of Service** | Credential stuffing saturating server resources. | Account lockout threshold; rate-limited session invalidation. |
| **Elevation of Privilege** | Unauthenticated user accesses student dashboard. | Strict FastAPI dependency injection (`get_current_user`) enforcing active non-revoked session cookies. |
