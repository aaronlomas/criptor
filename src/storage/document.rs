// Document persistence. Content columns hold ciphertext produced by the vault layer.

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use uuid::Uuid;
use crate::error::CriptorResult;

/// A row from the `documents` table as returned to the frontend.
#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct DocumentRow {
    pub id: String,
    pub title: String,
    pub encrypted_description: Option<String>,
    pub encrypted_content: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Inserts a new document row and returns its generated id.
pub async fn add_document(
    pool: &SqlitePool,
    title: &str,
    encrypted_description: Option<&str>,
    encrypted_content: &str,
) -> CriptorResult<String> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        r"INSERT INTO documents
           (id, title, encrypted_description, encrypted_content, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(title)
    .bind(encrypted_description)
    .bind(encrypted_content)
    .bind(&now)
    .bind(&now)
    .execute(pool)
    .await?;

    Ok(id)
}

/// Fetches all document rows, most recently updated first.
pub async fn get_documents(pool: &SqlitePool) -> CriptorResult<Vec<DocumentRow>> {
    let rows = sqlx::query_as::<_, DocumentRow>(
        r"SELECT id, title, encrypted_description, encrypted_content, created_at, updated_at
           FROM documents ORDER BY updated_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Fetches a single document by id.
pub async fn get_document_by_id(pool: &SqlitePool, id: &str) -> CriptorResult<Option<DocumentRow>> {
    let rows = sqlx::query_as::<_, DocumentRow>(
        r"SELECT id, title, encrypted_description, encrypted_content, created_at, updated_at
           FROM documents WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(rows)
}

/// Updates a document's fields.
pub async fn update_document(
    pool: &SqlitePool,
    id: &str,
    title: &str,
    encrypted_description: Option<&str>,
    encrypted_content: &str,
) -> CriptorResult<()> {
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        r"UPDATE documents
           SET title = ?, encrypted_description = ?, encrypted_content = ?, updated_at = ?
           WHERE id = ?",
    )
    .bind(title)
    .bind(encrypted_description)
    .bind(encrypted_content)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Deletes a document by id.
pub async fn delete_document(pool: &SqlitePool, id: &str) -> CriptorResult<()> {
    sqlx::query("DELETE FROM documents WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
