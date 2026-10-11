# Criptor — SDK Usage Guide

This guide walks through the public API of `CriptorClient`, the recommended entry point for
embedding Criptor in an application. All client methods are asynchronous and return
`Result<T, String>`; error strings are safe to surface to end users (they never leak paths or
schema details).

- [1. Installation](#1-installation)
- [2. Vault lifecycle](#2-vault-lifecycle)
- [3. Secret types](#3-secret-types)
- [4. Accounts](#4-accounts)
- [5. PINs](#5-pins)
- [6. Documents](#6-documents)
- [7. Groups](#7-groups)
- [8. Preferences](#8-preferences)
- [9. TOTP two-factor authentication](#9-totp-two-factor-authentication)
- [10. Audit logs](#10-audit-logs)
- [11. Export and import](#11-export-and-import)
- [12. Utilities](#12-utilities)
- [13. Error handling](#13-error-handling)
- [14. Concurrency](#14-concurrency)
- [15. Complete example](#15-complete-example)

## 1. Installation

```toml
[dependencies]
criptor = { git = "https://github.com/aaronlomas/criptor", branch = "main" }
tokio = { version = "1", features = ["full"] }
```

## 2. Vault lifecycle

### Create the client

```rust
use criptor::CriptorClient;
use std::path::PathBuf;

// Auxiliary files (vault.salt, unlock lock, background images) default to the
// database's parent directory.
let client = CriptorClient::new(PathBuf::from("/path/to/data/vault.bvda"));

// Or point them to a dedicated directory.
let client = client.with_base_dir(PathBuf::from("/path/to/data"));
```

`CriptorClient` is cheap to clone (it shares its state behind `Arc`).

### Check whether the vault exists

```rust
if client.is_vault_initialized() {
    // An existing vault (database and/or salt file) is present.
}
```

### Unlock

Unlocking creates the salt and the database on first use, and opens them afterwards:

```rust
use criptor::SecretString;

let status = client
    .unlock_vault(SecretString::new("correct horse battery staple".to_string()))
    .await?;

match status.as_str() {
    "unlocked" => { /* vault ready to use */ }
    "totp_required" => { /* see section 9 */ }
    _ => unreachable!(),
}
```

After 10 consecutive failed attempts, unlocking is blocked for one hour. Attempts are tracked in
`<base_dir>/.vault_unlock_lock`.

### Lock, check state, verify, delete

```rust
client.lock_vault();          // Drops the engine and clears the session.
let locked = client.is_locked();

// Verify a password without replacing the active session.
let ok: bool = client.verify_master_password(SecretString::new("...".to_string())).await?;

// Irreversibly delete the database and salt (requires the password).
client.delete_vault(SecretString::new("...".to_string())).await?;
```

## 3. Secret types

Plaintext secrets cross the API as `criptor::SecretString`, which zeroizes its buffer on drop.
Convert to `SecretString` with `SecretString::new(String)` and read it back with `.as_str()`.

Ciphertext is passed around as plain `&str`. Decrypt a stored ciphertext explicitly:

```rust
let password: String = client.decrypt_secret(&account.password_cipher).await?;
```

Every call to `decrypt_secret` records a `SecretAccess` entry in the audit log.

## 4. Accounts

```rust
let id: String = client
    .add_account(
        SecretString::new("example.com".to_string()), // site
        SecretString::new("alice".to_string()),       // username
        SecretString::new("s3cr3t".to_string()),      // password
        SecretString::new(String::new()),             // recovery code ("" = none)
        SecretString::new(String::new()),             // notes ("" = none)
    )
    .await?;

let accounts: Vec<criptor::Account> = client.get_accounts().await?;
for a in &accounts {
    let password = client.decrypt_secret(&a.password_cipher).await?;
    println!("{}: {} / {}", a.site, a.username, password);
}

client.delete_account(&id).await?;
```

`Account` fields: `id`, `site`, `username`, `password_cipher`, `recovery_code_cipher`,
`notes_cipher`, `favicon_url`, `group_name`, `created_at`, `updated_at`.

## 5. PINs

```rust
let id = client
    .add_pin(
        SecretString::new("Bank card".to_string()),
        SecretString::new("1234".to_string()),
        SecretString::new("ATM".to_string()), // notes ("" = none)
    )
    .await?;

let pins: Vec<criptor::Pin> = client.get_pins().await?;
client.update_pin_group(&id, Some("Finance")).await?;
client.delete_pin(&id).await?;
```

`Pin` fields: `id`, `name`, `encrypted_pin`, `encrypted_notes`, `group_name`, `created_at`,
`updated_at`.

## 6. Documents

Documents store a title, an optional description and free-form content, all encrypted.

```rust
let id = client
    .add_document(
        SecretString::new("Recovery plan".to_string()),
        Some(SecretString::new("Step-by-step".to_string())), // description (None = none)
        SecretString::new("1. ...\n2. ...".to_string()),     // content
    )
    .await?;

let docs: Vec<criptor::Document> = client.get_documents().await?;

client
    .update_document(
        &id,
        SecretString::new("Recovery plan v2".to_string()),
        Some(SecretString::new("Updated".to_string())),
        SecretString::new("...".to_string()),
    )
    .await?;

for d in &docs {
    let content = client.decrypt_document_content(&d.encrypted_content).await?;
    println!("{}: {}", d.title, content);
}

client.delete_document(&id).await?;
```

`Document` fields: `id`, `title`, `encrypted_description`, `encrypted_content`, `created_at`,
`updated_at`.

## 7. Groups

Groups are plain labels attached to accounts and PINs.

```rust
client.update_account_group(&account_id, Some("Work")).await?;
client.rename_group("Work", "Work / Production").await?;
client.delete_group("Finance").await?;
```

Passing `None` removes an item from its group.

## 7b. Preferences

Key/value settings stored inside the vault:

```rust
client.set_preference("security.block_remote", Some("true".to_string())).await?;
let value: Option<String> = client.get_preference("security.block_remote").await?;
client.set_preference("security.block_remote", None).await?; // delete
```

## 9. TOTP two-factor authentication

TOTP is optional and gates the session after unlock.

### Enable

```rust
let payload = client.totp_setup().await?;
// TotpSetupPayload { otpauth_url, qr_png_b64, recovery_codes }
// Show `qr_png_b64` (base64 PNG) or the otpauth URL, then confirm a code:
let ok = client.totp_verify_setup(&code).await?; // code from the authenticator app
```

Store `recovery_codes` securely; they are single-use.

### Unlock with TOTP enabled

```rust
let status = client.unlock_vault(password).await?; // "totp_required"
if status == "totp_required" {
    // Either a TOTP code...
    client.totp_check(&code).await?;
    // ...or a recovery code.
    client.totp_recovery_check(&recovery_code).await?;
}
```

Until `totp_check`/`totp_recovery_check` succeeds, every data method returns
`"Session not verified. TOTP authentication required."`.

### Inspect and disable

```rust
let enabled: bool = client.totp_is_enabled().await?;
client.totp_disable().await?;
```

## 10. Audit logs

```rust
let logs: Vec<criptor::client::AuditLogView> = client.get_audit_logs(100).await?;
println!("default limit: {}", client.get_audit_log_limit());
client.clear_audit_logs().await?;
```

`AuditLogView` fields: `id`, `action`, `metadata`, `created_at`.

## 11. Export and import

### Raw database backup (same key)

```rust
client.export_db("/backups/vault.bvda").await?;
```

Copies the database **and** the matching salt file (`vault.bvda.salt`) next to it. The backup
opens with the same master password. Always keep the salt together with the database.

To restore a raw backup, stop using the current vault and hand the file to the client:

```rust
client.prepare_import_db("/backups/vault.bvda").await?; // releases the pool before overwriting
```

### Encrypted package (independent export password)

```rust
use criptor::vault::ImportStrategy;

client
    .export_secure_package("/backups/vault.bvda.pack", "export-password".to_string())
    .await?;

client
    .import_secure_package(
        "/backups/vault.bvda.pack",
        "export-password".to_string(),
        ImportStrategy::Merge, // or ImportStrategy::Replace
    )
    .await?;
```

The `.bvda.pack` container uses its own key derived from a fresh salt and the export password;
it is not tied to the master password.

## 12. Utilities

```rust
use criptor::CriptorClient;

// Cryptographically strong password generator (length clamped to 8..=128).
let password = CriptorClient::generate_password(24, true)?;

// Background image handling (stored under <base_dir>).
let filename: String = client.import_background_image("/path/to/image.png").await?;
let data_url: String = client.get_background_data_url(&filename)?;

let dir: String = client.get_data_dir();
```

## 13. Error handling

Client methods return `Result<T, String>`. The engine layer returns
`Result<T, criptor::CriptorError>`, whose variants include `VaultLocked`,
`RemoteSessionDetected`, `InvalidPassword`, `InvalidTotpCode`, `InputTooLong`, `EmptyInput`,
`NotFound` and `Other`. User-facing strings are intentionally generic to avoid leaking sensitive
details.

```rust
match client.unlock_vault(password).await {
    Ok(status) => { /* ... */ }
    Err(msg) => eprintln!("Unlock failed: {msg}"),
}
```

## 14. Concurrency

`CriptorClient` is `Clone` and shares its engine behind an `Arc<Mutex<..>>`. Cloning is the
intended way to share a client across tasks; there is one engine (and one connection pool) per
locked session. A background guard that clears only the master key still makes `is_locked()`
report `true`.

## 15. Complete example

```rust
use criptor::{CriptorClient, SecretString};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = CriptorClient::new(PathBuf::from("./data/vault.bvda"));

    let status = client
        .unlock_vault(SecretString::new("master-password".to_string()))
        .await?;
    assert_eq!(status, "unlocked");

    let id = client
        .add_account(
            SecretString::new("example.com".to_string()),
            SecretString::new("alice".to_string()),
            SecretString::new("s3cr3t".to_string()),
            SecretString::new(String::new()),
            SecretString::new(String::new()),
        )
        .await?;

    for a in client.get_accounts().await? {
        let password = client.decrypt_secret(&a.password_cipher).await?;
        println!("{} -> {}", a.site, password);
    }

    client.delete_account(&id).await?;
    client.lock_vault();
    Ok(())
}
```
