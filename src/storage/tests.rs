use super::*;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

async fn setup_db() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    init_db(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn test_db_init() {
    let pool = setup_db().await;
    // Check if tables exist
    let tables: Vec<(String,)> = sqlx::query_as("SELECT name FROM sqlite_master WHERE type='table'")
        .fetch_all(&pool)
        .await
        .unwrap();
    let table_names: Vec<String> = tables.into_iter().map(|(n,)| n).collect();
    assert!(!table_names.contains(&"vault_meta".to_string()), "vault_meta must not exist: salt lives in vault.salt on disk");
    assert!(table_names.contains(&"accounts".to_string()));
    assert!(table_names.contains(&"preferences".to_string()));
}

#[tokio::test]
async fn test_crud_accounts() {
    let pool = setup_db().await;

    let id = add_account(&pool, "site.com", "user", "pass", None, Some("notes"), Some("favicon")).await.unwrap();
    let accounts = get_accounts(&pool).await.unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id, id);
    assert_eq!(accounts[0].site, "site.com");

    update_account_group(&pool, &id, Some("Work")).await.unwrap();
    let accounts = get_accounts(&pool).await.unwrap();
    assert_eq!(accounts[0].group_name, Some("Work".to_string()));

    delete_account(&pool, &id).await.unwrap();
    let accounts = get_accounts(&pool).await.unwrap();
    assert_eq!(accounts.len(), 0);
}

#[tokio::test]
async fn test_preferences() {
    let pool = setup_db().await;

    set_preference(&pool, "theme", "dark").await.unwrap();
    let val = get_preference(&pool, "theme").await.unwrap();
    assert_eq!(val, Some("dark".to_string()));

    set_preference(&pool, "theme", "light").await.unwrap();
    let val = get_preference(&pool, "theme").await.unwrap();
    assert_eq!(val, Some("light".to_string()));

    let non_existent = get_preference(&pool, "non_existent").await.unwrap();
    assert_eq!(non_existent, None);
}

#[tokio::test]
async fn test_group_operations_tx() {
    let pool = setup_db().await;
    add_account(&pool, "s1", "u", "p", None, None, None).await.unwrap();
    let id2 = add_account(&pool, "s2", "u", "p", None, None, None).await.unwrap();
    update_account_group(&pool, &id2, Some("G1")).await.unwrap();

    let mut tx = pool.begin().await.unwrap();
    rename_group_tx(&mut tx, "G1", "G2").await.unwrap();
    tx.commit().await.unwrap();

    let count = count_accounts_in_group(&pool, "G2").await.unwrap();
    assert_eq!(count, 1);

    let mut tx = pool.begin().await.unwrap();
    delete_group_tx(&mut tx, "G2").await.unwrap();
    tx.commit().await.unwrap();

    let count = count_accounts_in_group(&pool, "G2").await.unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_audit_log_prune_respects_cap() {
    let pool = setup_db().await;

    // Insert more rows than the cap to trigger pruning.
    let over_cap = (AUDIT_LOG_MAX_ROWS + 5) as usize;
    for i in 0..over_cap {
        add_audit_log(&pool, "vault_unlock", Some(&format!("entry {i}"))).await.unwrap();
    }

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, AUDIT_LOG_MAX_ROWS, "Row count must equal the cap after pruning");
}

#[tokio::test]
async fn test_audit_log_clear() {
    let pool = setup_db().await;

    add_audit_log(&pool, "vault_lock", None).await.unwrap();
    add_audit_log(&pool, "vault_unlock", Some("ok")).await.unwrap();

    clear_audit_log(&pool).await.unwrap();

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0, "Table must be empty after clear");
}

#[tokio::test]
async fn test_audit_log_retains_newest() {
    let pool = setup_db().await;

    // Insert cap + 3 rows; the 3 oldest must be pruned.
    let total = (AUDIT_LOG_MAX_ROWS + 3) as usize;
    for i in 0..total {
        add_audit_log(&pool, "secret_access", Some(&format!("seq {i}"))).await.unwrap();
    }

    // The oldest surviving row should have metadata "seq 3" (0-based).
    let rows = get_audit_logs(&pool, AUDIT_LOG_MAX_ROWS).await.unwrap();
    assert_eq!(rows.len() as i64, AUDIT_LOG_MAX_ROWS);

    let oldest = rows.last().unwrap();
    assert_eq!(oldest.2.as_deref(), Some("seq 3"));
}
