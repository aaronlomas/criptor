// Database schema initialization and legacy migrations.

use crate::error::CriptorResult;
use sqlx::SqlitePool;

/// Initializes the database schema, creating every table if it does not exist.
pub async fn init_db(pool: &SqlitePool) -> CriptorResult<()> {
    sqlx::query(
        r"
        -- vault_meta was removed: the KDF salt is stored as `vault.salt` on the filesystem
        -- (see vault/authentication CriptorEngine::unlock). There is no salt in the DB.
        CREATE TABLE IF NOT EXISTS accounts (
            id                  TEXT PRIMARY KEY,
            site                TEXT NOT NULL,
            username            TEXT NOT NULL,
            encrypted_password  TEXT NOT NULL,
            encrypted_recovery_code TEXT,
            encrypted_notes     TEXT,
            favicon_url         TEXT,
            group_name          TEXT,
            created_at          TEXT NOT NULL,
            updated_at          TEXT NOT NULL
        );

        -- Index for fast sorting and searching by site
        CREATE INDEX IF NOT EXISTS idx_accounts_site ON accounts(site);
        -- Index for fast filtering by group
        CREATE INDEX IF NOT EXISTS idx_accounts_group ON accounts(group_name);

        CREATE TABLE IF NOT EXISTS pins (
            id              TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            encrypted_pin   TEXT NOT NULL,
            encrypted_notes TEXT,
            group_name      TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents (
            id                      TEXT PRIMARY KEY,
            title                   TEXT NOT NULL,
            encrypted_description   TEXT,
            encrypted_content       TEXT NOT NULL,
            created_at              TEXT NOT NULL,
            updated_at              TEXT NOT NULL
        );
        ",
    )
    .execute(pool)
    .await?;

    // Audit Log table
    sqlx::query(
        r"CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            action      TEXT NOT NULL,
            metadata    TEXT,
            created_at  TEXT NOT NULL
        );",
    )
    .execute(pool)
    .await?;

    // Preferences table
    sqlx::query(
        r"CREATE TABLE IF NOT EXISTS preferences (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );",
    )
    .execute(pool)
    .await?;

    // TOTP Recovery Codes table (Security segregation)
    sqlx::query(
        r"CREATE TABLE IF NOT EXISTS totp_recovery_codes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            code_cipher TEXT NOT NULL
        );",
    )
    .execute(pool)
    .await?;

    // Handle legacy schema updates gracefully
    // Note: vault_meta is intentionally absent — the KDF salt lives in `vault.salt` on disk.
    let _ = sqlx::query("ALTER TABLE accounts ADD COLUMN group_name TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE accounts ADD COLUMN encrypted_recovery_code TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE accounts ADD COLUMN favicon_url TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE pins ADD COLUMN group_name TEXT")
        .execute(pool)
        .await;

    Ok(())
}
