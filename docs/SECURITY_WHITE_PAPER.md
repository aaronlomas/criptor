# Criptor: Security White Paper

This document details the security architecture, cryptographic design, and memory hardening measures implemented in **Criptor**. Our goal is to provide full transparency for users and security auditors.

---

## 1. Security Philosophy: "Security by Isolation"

Criptor is designed around the principle of strict process isolation. The core engine functions as a black box that handles secrets exclusively within protected memory, exposing a minimal interface (Facade) to radically reduce the attack surface. The system is entirely **Zero-Knowledge**: all data never leaves the user's device, and the developer has no technical means to recover master passwords.

## 2. Cryptographic Stack

Criptor uses modern, resilient, and high-performance cryptographic primitives:



| Function | Algorithm | Rationale |
| :--- | :--- | :--- |
| **KDF (Key Derivation Function)** | Argon2id | Winner of the Password Hashing Competition; highly resistant to GPU/ASIC brute-force attacks. |
| **Symmetric Encryption** | ChaCha20-Poly1305 | Authenticated Encryption with Associated Data (AEAD); extremely fast and secure, preferred over AES on systems lacking dedicated hardware acceleration. |
| **Database Encryption** | SQLCipher — AES-256-CBC + HMAC-SHA512 | Industry standard for transparent SQLite database encryption. Pages are encrypted with AES-256-CBC and authenticated with HMAC-SHA512 (encrypt-then-MAC); the cipher key is derived with PBKDF2-HMAC-SHA512 (256,000 iterations, 4096-byte pages). All parameters are pinned explicitly in code rather than relying on compiled-in defaults. |
| **Entropy Generation** | `rand::rngs::OsRng` | Leverages the operating system's cryptographically secure pseudorandom number generator (CSPRNG). |

---

## 3. Key Management and Hierarchy

### 3.1 Master Key Derivation
The master password is never stored anywhere on the system. Upon unlocking the vault:
1. The `vault.salt` is read (32 random bytes generated during initialization).
2. **Argon2id** is executed to derive a 256-bit key.
3. Default parameters are optimized for local desktop security:
   - Time: 3 iterations.
   - Memory: 64 MB.
   - Parallelism: 4 threads.

### 3.2 In-Memory Key Protection
Once derived, the **Master Key** is wrapped inside a `MasterKey` struct that strictly enforces:
- **mlock / VirtualLock:** Locks the underlying physical memory pages to prevent the operating system from moving the key into the swap file or pagefile on the disk.
- **Zeroization:** Physically overwrites the key's raw bytes with zeros the exact moment the struct goes out of scope (`Drop`).

---

## 4. Process Hardening

### 4.1 Anti-Forensics (Linux/Unix/Windows)
Upon startup, Criptor executes preventive security measures at the OS level:
- **Linux:** Calls `prctl(PR_SET_DUMPABLE, 0)` to disable core dumps and prevent unprivileged processes from attaching via `ptrace`.
- **Windows:** Configures `SetErrorMode` to prevent system error dialogs that could inadvertently write crash dumps to disk.

### 4.2 Debugger Attachment Detection
Criptor can report whether the *current* process is attached to a debugger, which is exposed
through `security::debugger_evidence()` and rendered by the `status` shell command:
- **Linux:** Reads `TracerPid` from `/proc/self/status`; a non-zero value identifies the tracer.
- **Windows:** Uses `IsDebuggerPresent()` from the `Win32_System_Diagnostics_Debug` API.
- **macOS:** Reads the process flags returned by the `KERN_PROC` sysctl and inspects the `P_TRACED` flag.

This check is **read-only and observational**: it never blocks an operation, it does not attach to
other processes and it does not attempt to terminate the tracer. Host applications decide what
to do with the result.

Separately, the `sysinfo` shell command lists processes whose executable name matches a known
reverse-engineering, debugging or traffic capture tool. This detection is a **name-based
heuristic**, not a security boundary: it can be evaded by renaming an executable, it can produce
false positives and it never blocks any operation.

### 4.3 Transparent and Double-Layer Encryption
The entire SQLite database file is encrypted by SQLCipher. Additionally, Criptor enforces a **second layer of encryption** (Application-Layer Encryption): every sensitive field (username, password, notes, URL) is individually encrypted using ChaCha20-Poly1305 before database insertion. Even in the hypothetical event of an SQLCipher key compromise, the underlying secrets remain fully protected.

---

## 5. Multi-Factor Authentication (TOTP)

Criptor supports TOTP (RFC 6238) as an optional second factor for vault decryption:
- The TOTP secret is stored encrypted using the user's Master Key.
- Single-use **recovery codes** are generated and stored under encryption to prevent permanent lockouts in case the authentication device is lost.

---

## 6. Traceability and Audit Logs (SOC2 Readiness)

Every sensitive operation is recorded in an immutable audit log stored directly within the encrypted database:
- Successful and failed unlock attempts.
- Secret exposure events (every time a user reveals a password).
- Data import and export actions.
- Changes to core security settings.

---

## 7. Export Format (.bvda.pack)

The export format is an encrypted binary container that utilizes:
- An independent export key derived using a fresh cryptographic salt and a specific export password.
- An in-memory data pipeline that decrypts and re-encrypts records on the fly, guaranteeing that secrets never touch the disk layout in plaintext during the export process.

---

## 8. Security Considerations
- **Side-Channel Resistance:** Constant-time comparison primitives (via the `subtle` crate) are used for critical authentication and TOTP verification flows.
- **Data Validation:** All inputs are strictly sanitized and validated to mitigate injection attacks or buffer overflows before reaching the cryptographic sub-layer.
