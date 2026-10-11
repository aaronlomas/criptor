// Account persistence. All secret columns hold ciphertext produced by the vault layer.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;
use crate::error::CriptorResult;

/// A row from the `accounts` table as returned to the frontend.
#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct AccountRow {
    pub id: String,
    pub site: String,
    pub username: String,
    pub encrypted_password: String,
    pub encrypted_recovery_code: Option<String>,
    pub encrypted_notes: Option<String>,
    pub favicon_url: Option<String>,
    pub group_name: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Inserts a new account row and returns its generated id.
pub async fn add_account(
    pool: &SqlitePool,
    site: &str,
    username: &str,
    encrypted_password: &str,
    encrypted_recovery_code: Option<&str>,
    encrypted_notes: Option<&str>,
    favicon_url: Option<&str>,
) -> CriptorResult<String> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        r"INSERT INTO accounts
           (id, site, username, encrypted_password, encrypted_recovery_code, encrypted_notes, favicon_url, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(site)
    .bind(username)
    .bind(encrypted_password)
    .bind(encrypted_recovery_code)
    .bind(encrypted_notes)
    .bind(favicon_url)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Fetches all account rows ordered by site.
pub async fn get_accounts(pool: &SqlitePool) -> CriptorResult<Vec<AccountRow>> {
    let rows = sqlx::query_as::<_, AccountRow>(
        r"SELECT id, site, username, encrypted_password, encrypted_recovery_code,
                  encrypted_notes, favicon_url, group_name, created_at, updated_at
           FROM accounts ORDER BY site ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Fetches a page of account rows ordered by site.
pub async fn get_accounts_paged(pool: &SqlitePool, limit: i64, offset: i64) -> CriptorResult<Vec<AccountRow>> {
    let rows = sqlx::query_as::<_, AccountRow>(
        r"SELECT id, site, username, encrypted_password, encrypted_recovery_code,
                  encrypted_notes, favicon_url, group_name, created_at, updated_at
           FROM accounts ORDER BY site ASC LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Deletes an account by id.
pub async fn delete_account(pool: &SqlitePool, id: &str) -> CriptorResult<()> {
    sqlx::query("DELETE FROM accounts WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
