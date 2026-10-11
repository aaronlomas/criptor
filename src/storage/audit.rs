// Audit log persistence.

use sqlx::SqlitePool;
use crate::error::CriptorResult;

/// Maximum number of audit log rows retained at any time.
/// Rows older than this cap are pruned automatically on each insert.
pub const AUDIT_LOG_MAX_ROWS: i64 = 1_000;

/// Adds a new audit entry and prunes rows beyond [`AUDIT_LOG_MAX_ROWS`].
pub async fn add_audit_log(
    pool: &SqlitePool,
    action: &str,
    metadata: Option<&str>,
) -> CriptorResult<()> {
    sqlx::query("INSERT INTO audit_log (action, metadata, created_at) VALUES (?, ?, ?)")
        .bind(action)
        .bind(metadata)
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(pool)
        .await?;

    prune_audit_log(pool).await?;
    Ok(())
}

/// Deletes all audit rows beyond the [`AUDIT_LOG_MAX_ROWS`] cap.
pub async fn prune_audit_log(pool: &SqlitePool) -> CriptorResult<()> {
    sqlx::query(
        "DELETE FROM audit_log \
         WHERE id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT ?)",
    )
    .bind(AUDIT_LOG_MAX_ROWS)
    .execute(pool)
    .await?;
    Ok(())
}

/// Removes every audit log row.
pub async fn clear_audit_log(pool: &SqlitePool) -> CriptorResult<()> {
    sqlx::query("DELETE FROM audit_log")
        .execute(pool)
        .await?;
    Ok(())
}

/// Fetches the most recent audit logs.
pub async fn get_audit_logs(pool: &SqlitePool, limit: i64) -> CriptorResult<Vec<(i64, String, Option<String>, String)>> {
    let rows: Vec<(i64, String, Option<String>, String)> =
        sqlx::query_as("SELECT id, action, metadata, created_at FROM audit_log ORDER BY id DESC LIMIT ?")
            .bind(limit)
            .fetch_all(pool)
            .await?;
    Ok(rows)
}
