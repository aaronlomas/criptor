// Group persistence: group assignment for accounts/pins and bulk group operations.

use crate::error::CriptorResult;
use sqlx::{SqliteConnection, SqlitePool};

/// Assigns (or clears) an account's group.
pub async fn update_account_group(
    pool: &SqlitePool,
    id: &str,
    group_name: Option<&str>,
) -> CriptorResult<()> {
    sqlx::query("UPDATE accounts SET group_name = ?, updated_at = ? WHERE id = ?")
        .bind(group_name)
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Renames a group across all accounts and pins (transactional).
pub async fn rename_group_tx(
    conn: &mut SqliteConnection,
    old_name: &str,
    new_name: &str,
) -> CriptorResult<()> {
    sqlx::query("UPDATE accounts SET group_name = ?, updated_at = ? WHERE group_name = ?")
        .bind(new_name)
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(old_name)
        .execute(&mut *conn)
        .await?;

    sqlx::query("UPDATE pins SET group_name = ?, updated_at = ? WHERE group_name = ?")
        .bind(new_name)
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(old_name)
        .execute(&mut *conn)
        .await?;

    Ok(())
}

/// Removes a group association from all accounts and pins (transactional).
pub async fn delete_group_tx(conn: &mut SqliteConnection, name: &str) -> CriptorResult<()> {
    sqlx::query("UPDATE accounts SET group_name = NULL, updated_at = ? WHERE group_name = ?")
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(name)
        .execute(&mut *conn)
        .await?;

    sqlx::query("UPDATE pins SET group_name = NULL, updated_at = ? WHERE group_name = ?")
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(name)
        .execute(&mut *conn)
        .await?;

    Ok(())
}

/// Counts how many accounts belong to a given group.
pub async fn count_accounts_in_group(pool: &SqlitePool, group_name: &str) -> CriptorResult<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM accounts WHERE group_name = ?")
        .bind(group_name)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}
