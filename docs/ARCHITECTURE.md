# Criptor — Internal Architecture

This document describes the logical structure of the Criptor engine: how the code is layered,
what each module is responsible for, and how data flows through the system.

## 1. Design principles

1. **Strict layering.** Cryptographic primitives, persistence and application logic never leak
   into each other. A module only calls the layer directly below it.
2. **Secret isolation.** Key material lives only inside the engine. Higher layers handle secrets
   through zeroizing wrappers and never inspect raw bytes.
3. **One responsibility per module.** Each domain entity (accounts, pins, documents, groups, …)
   owns its own encrypt-and-persist flow.
4. **Framework-agnostic facade.** The public surface is a thin, async facade that can be wrapped
   by a Tauri command layer, a CLI, or an FFI boundary without change.

## 2. Public entry points

Criptor exposes two entry points from `src/lib.rs`. The crate root re-exports the types an
embedder needs: `CriptorEngine`, `MasterKey`, `CriptorClient`, `Account`, `Pin`, `Document`,
`SecretKey`, `SecretString`, `CriptorError`, `CriptorResult`, and `harden_process()`.

### `CriptorEngine` (core)

Owns:

- a `SqlitePool` (`sqlx`) connected to the encrypted database;
- the master key, stored as `Arc<Mutex<Option<MasterKey>>>`.

It is created with `CriptorEngine::unlock(db_path, password)` and exposes the entity operations
directly. It is the right entry point when the caller already manages the vault path and password
and does not need the session/TOTP gating provided by the client.

### `CriptorClient` (facade)

A cloneable struct holding:

- `engine: Arc<Mutex<Option<CriptorEngine>>>` — the unlocked engine, or `None` when locked;
- `session_verified: Arc<Mutex<bool>>` — whether TOTP (if enabled) has been satisfied;
- `db_path: PathBuf` — the vault database file;
- `base_dir: PathBuf` — directory for auxiliary files (salt, unlock lock file, background images).
  Defaults to the database's parent directory and can be overridden with `with_base_dir`.

Every client method delegates to the engine through `get_engine()`, which fails with
`"Vault is locked"` or `"Session not verified. TOTP authentication required."` when appropriate.
This is the recommended entry point for applications and for Tauri/FFI command layers.

## 3. Layer map

```
┌──────────────────────────────────────────────────────────────┐
│ client/                 application facade (async, UI-agnostic)
├──────────────────────────────────────────────────────────────┤
│ vault/                  domain orchestration (CriptorEngine)
│   ├─ authentication     lifecycle, KDF, unlock/lock, DB opening
│   ├── account / pin     encrypt-then-persist per entity
│   ├── document / group
│   ├── totp              TOTP storage and verification
│   ├── export            .bvda.pack container
│   ├── export_import     export/import orchestration
│   └── validation        input validation
├──────────────────────────────────────────────────────────────┤
│ storage                 SQLCipher pool, schema, models, CRUD
│ crypto                  KDF, AEAD, secret wrappers
├──────────────────────────────────────────────────────────────┤
│ cross-cutting           auth, audit, security, error
└──────────────────────────────────────────────────────────────┘
```

## 4. Module map

| Module | Path | Responsibility |
| :--- | :--- | :--- |
| `crypto` | `src/crypto/mod.rs` | Key derivation (Argon2id), ChaCha20-Poly1305 AEAD, password generation. |
| `crypto::secret` | `src/crypto/secret.rs` | `SecretKey` and `SecretString`: zeroizing wrappers for sensitive bytes. |
| `storage` | `src/storage/mod.rs` | SQLCipher pool lifecycle, schema creation (`init_db`), CRUD, preferences and audit persistence. |
| `storage::models` | `src/storage/models.rs` | Persisted models `Account`, `Pin`, `Document`; sensitive columns hold ciphertext. |
| `vault` | `src/vault/mod.rs` | `CriptorEngine`, `MasterKey`, `ImportStrategy`; orchestrates the domain. |
| `vault::authentication` | `src/vault/authentication/mod.rs` | Salt handling, KDF, unlock/lock, opening the encrypted database with pinned PRAGMAs. |
| `vault::{account,pin,document,group}` | `src/vault/*/mod.rs` | Encrypt-then-persist flows, one module per entity. |
| `vault::totp` | `src/vault/totp/mod.rs` | TOTP secret storage, verification and recovery codes. |
| `vault::export` / `vault::export_import` | `src/vault/export*.rs` | `.bvda.pack` container build/parse and high-level import orchestration. |
| `vault::validation` | `src/vault/validation.rs` | Input validation shared by the entity modules. |
| `client` | `src/client.rs` + `src/client/*` | Application facade. Holds the session lock state; mirrors the domain in submodules. |
| `auth` | `src/auth/` | TOTP primitives and payloads (`TotpManager`, `TotpSetupPayload`). |
| `audit` | `src/audit/` | Audit action catalog (`AuditAction`). |
| `security` | `src/security/mod.rs` | Environment checks (for example, remote session detection). |
| `error` | `src/error.rs` | Unified `CriptorError` and `CriptorResult`. |

The `client` submodules are `account`, `pin`, `document`, `group`, `preferences`, `totp`,
`audit_log`, `export_import`, `utilities` and `shell`.

## 5. Data flow

### Unlock

1. `CriptorClient::unlock_vault` checks the failed-attempt lock file (`.vault_unlock_lock`),
   enforcing a cool-down after 10 failed attempts.
2. `CriptorEngine::unlock` reads `vault.salt` (creating a fresh 32-byte salt on first use),
   derives the master key with Argon2id, and opens the database with all SQLCipher PRAGMAs pinned.
- Initializing the schema both creates a new vault and verifies the key on an existing one: a
  wrong password fails here and maps to `CriptorError::InvalidPassword`.
- If TOTP is enabled, the client stores the engine but keeps `session_verified = false` and
  returns `"totp_required"`; `totp_check` (or `totp_recovery_check`) then flips it to `true`.

### Writing a secret

1. The `client` delegates to the `vault` entity module.
2. The `vault` module encrypts each sensitive field with `crypto` (ChaCha20-Poly1305) using the
   in-memory master key.
3. The resulting ciphertext is persisted through `storage` into the SQLCipher database.

### Reading a secret

1. `storage` returns the model row whose sensitive columns are ciphertext.
2. The caller calls `decrypt_secret` (or `decrypt_document_content`), which delegates to the
   `vault`/`crypto` layers and logs a `SecretAccess` audit entry.

## 6. Cryptographic boundaries

- The master key exists only inside `MasterKey`: heap-allocated, pinned with `mlock`/`VirtualLock`
  and zeroized on drop.
- Field encryption/decryption happens only in `crypto`, invoked by the `vault` layer. The `client`
  layer never touches key material.
- All plaintext secrets cross the API as `SecretString`; the caller must explicitly convert to an
  owned `String` to observe a value.

## 7. Adding a new entity

1. Add the persisted model in `storage::models` and its CRUD in `storage`.
2. Add a `vault::<entity>` module with the encrypt-then-persist operations on `CriptorEngine`.
3. Add a `client::<entity>` submodule exposing the operations through `CriptorClient`.
4. Re-export any new public type from `lib.rs`.
