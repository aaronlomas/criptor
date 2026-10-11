// PIN persistence. `encrypted_pin`/`encrypted_notes` hold ciphertext produced by the vault layer.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;
use crate::error::CriptorResult;

/// A row from the `pins` table as returned to the frontend.
#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct PinRow {
    pub id: String,
    pub name: String,
    pub encrypted_pin: String,
    pub encrypted_notes: Option<String>,
    pub group_name: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Inserts a new PIN row and returns its generated id.
pub async fn add_pin(
    pool: &SqlitePool,
    name: &str,
    encrypted_pin: &str,
    encrypted_notes: Option<&str>,
    group_name: Option<&str>,
) -> CriptorResult<String> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        r"INSERT INTO pins
           (id, name, encrypted_pin, encrypted_notes, group_name, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(name)
    .bind(encrypted_pin)
    .bind(encrypted_notes)
    .bind(group_name)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Fetches all PIN rows ordered by name.
pub async fn get_pins(pool: &SqlitePool) -> CriptorResult<Vec<PinRow>> {
    let rows = sqlx::query_as::<_, PinRow>(
        r"SELECT id, name, encrypted_pin, encrypted_notes, group_name, created_at, updated_at
           FROM pins ORDER BY name ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Deletes a PIN by id.
pub async fn delete_pin(pool: &SqlitePool, id: &str) -> CriptorResult<()> {
    sqlx::query("DELETE FROM pins WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Assigns (or clears) a PIN's group.
pub async fn update_pin_group(
    pool: &SqlitePool,
    id: &str,
    group_name: Option<&str>,
) -> CriptorResult<()> {
    sqlx::query("UPDATE pins SET group_name = ?, updated_at = ? WHERE id = ?")
        .bind(group_name)
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
