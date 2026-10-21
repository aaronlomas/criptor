# Criptor

Criptor is a framework-agnostic, local-first secrets and credential engine, distributed as a
Rust SDK. It provides an encrypted SQLite vault and a minimal async API to store credentials,
PINs and documents, manage groups and preferences, enable TOTP two-factor authentication, write
audit logs, and export/import encrypted packages.

Criptor has no UI, no network stack and no platform-specific opinions. It is the cryptographic
engine behind [Bóveda](https://github.com/aaronlomas/boveda), but it is designed to be embedded
in any Rust or FFI application (desktop app, CLI, service).

## Features

- **Encrypted at rest** — the whole database file is encrypted with SQLCipher.
- **Double-layer encryption** — every sensitive field is additionally encrypted with
  ChaCha20-Poly1305 before it reaches the database.
- **Zero-knowledge** — secrets never leave the device; the master password is never stored.
- **Memory hardening** — keys are pinned with `mlock`/`VirtualLock` and zeroized on drop.
- **Optional TOTP** — RFC 6238 second factor with QR setup and single-use recovery codes.
- **Encrypted packages** — `.bvda.pack` export/import with an independent export key.
- **Audit log** — every sensitive operation is recorded inside the encrypted database.
- **Environment introspection** — on-demand CPU, memory and process telemetry, plus detection
  of debuggers attached to the current process.

## Cryptographic stack

| Function | Algorithm | Notes |
| :--- | :--- | :--- |
| Master key derivation (KDF) | **Argon2id** | 64 MB memory, 3 iterations, 4 lanes. |
| Database encryption | **SQLCipher — AES-256-CBC** | Page integrity via **HMAC-SHA512** (encrypt-then-MAC); key derivation **PBKDF2-HMAC-SHA512**, 256,000 iterations, 4096-byte pages. |
| Field (application-layer) encryption | **ChaCha20-Poly1305** | AEAD over each secret field. |
| Entropy | `rand::rngs::OsRng` | OS CSPRNG. |

The SQLCipher cipher and KDF parameters are pinned explicitly in code and do **not** rely on
compiled-in defaults. See [`docs/SECURITY_WHITE_PAPER.md`](docs/SECURITY_WHITE_PAPER.md) for the
full design.

## Installation

Add Criptor as a git dependency:

```toml
[dependencies]
criptor = { git = "https://github.com/aaronlomas/criptor", branch = "main" }
tokio = { version = "1", features = ["full"] }
```

Criptor is asynchronous and expects a Tokio runtime.

## Quick start

```rust
use criptor::{CriptorClient, SecretString};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The database lives next to an auxiliary `vault.salt` file.
    let client = CriptorClient::new(PathBuf::from("./data/vault.bvda"));

    // First unlock creates the salt and database; later unlocks open it.
    let status = client
        .unlock_vault(SecretString::new("master-password".to_string()))
        .await?;
    assert_eq!(status, "unlocked"); // "totp_required" when TOTP is enabled

    // Store a credential.
    client
        .add_account(
            SecretString::new("example.com".to_string()),
            SecretString::new("alice".to_string()),
            SecretString::new("s3cr3t".to_string()),
            SecretString::new(String::new()),
            SecretString::new(String::new()),
        )
        .await?;

    // Read credentials back (secret columns stay encrypted until decrypted).
    for account in client.get_accounts().await? {
        let password = client.decrypt_secret(&account.password_cipher).await?;
        println!("{} -> {}", account.site, password);
    }

    client.lock_vault();
    Ok(())
}
```

See [`docs/USAGE.md`](docs/USAGE.md) for the full API walkthrough.

## Shell interface

`query_shell` exposes a text-driven interface that returns plain lines for the host application
to render:

| Command | Description |
| :--- | :--- |
| `help` | Lists the available commands. |
| `crypto` | Shows the active cryptographic parameters. |
| `status` | Vault state, session state, database path and a compact runtime block. |
| `sysinfo` | CPU, memory, swap, the process table and the detected analysis tools. |
| `sessions` | Shows the last 10 audit log entries (`-n <N>` and `-rm` are supported). |

The runtime and telemetry data is sampled on demand, rendered and discarded: it is never stored,
audited or transmitted.

## Documentation

- [`docs/USAGE.md`](docs/USAGE.md) — SDK usage guide.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — internal structure and data flow.
- [`docs/SECURITY_WHITE_PAPER.md`](docs/SECURITY_WHITE_PAPER.md) — security design.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — development roadmap.

## License

Criptor is free software licensed under **GPL-3.0-only** (see [`LICENSE`](LICENSE)).
