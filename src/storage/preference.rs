// Preferences (settings) persistence, with pool- and transaction-based variants.

use sqlx::{SqliteConnection, SqlitePool};
use crate::error::CriptorResult;

/// Gets a user preference by key.
pub async fn get_preference(pool: &SqlitePool, key: &str) -> CriptorResult<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM preferences WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(v,)| v))
}

/// Fetches every preference as a list of `(String, String)` pairs.
/// Note: preserves the original `SELECT value, key` column order.
pub async fn get_all_preferences(pool: &SqlitePool) -> CriptorResult<Vec<(String, String)>> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT value, key FROM preferences")
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

/// Reads a preference inside an existing transaction.
pub async fn get_preference_tx(conn: &mut SqliteConnection, key: &str) -> CriptorResult<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM preferences WHERE key = ?")
        .bind(key)
        .fetch_optional(conn)
        .await?;
    Ok(row.map(|(v,)| v))
}

/// Inserts or updates a preference.
pub async fn set_preference(pool: &SqlitePool, key: &str, value: &str) -> CriptorResult<()> {
    sqlx::query(
        "INSERT INTO preferences (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

/// Inserts or updates a preference inside an existing transaction.
pub async fn set_preference_tx(conn: &mut SqliteConnection, key: &str, value: &str) -> CriptorResult<()> {
    sqlx::query(
        "INSERT INTO preferences (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(value)
    .execute(conn)
    .await?;
    Ok(())
}

/// Deletes a preference by key.
pub async fn delete_preference(pool: &SqlitePool, key: &str) -> CriptorResult<()> {
    sqlx::query("DELETE FROM preferences WHERE key = ?")
        .bind(key)
        .execute(pool)
        .await?;
    Ok(())
}

/// Deletes a preference by key inside an existing transaction.
pub async fn delete_preference_tx(conn: &mut SqliteConnection, key: &str) -> CriptorResult<()> {
    sqlx::query("DELETE FROM preferences WHERE key = ?")
        .bind(key)
        .execute(conn)
        .await?;
    Ok(())
}
