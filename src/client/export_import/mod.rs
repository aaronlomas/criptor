use std::path::Path;

use path_clean::PathClean;

use crate::crypto::secret::SecretString;
use crate::vault::ImportStrategy;

impl super::CriptorClient {
    pub async fn export_db(&self, dest_path: &str) -> Result<(), String> {
        let dest_db = Path::new(dest_path).clean();
        if dest_db.as_os_str().is_empty() {
            return Err("Destination path cannot be empty".to_string());
        }

        let db_path = self.db_path.clean();

        // Prevent exporting over the active database file
        if dest_db == db_path {
            return Err("Cannot export to the same file the app is currently using.".to_string());
        }
        if let (Ok(can_dest), Ok(can_db)) = (dest_db.canonicalize(), db_path.canonicalize()) {
            if can_dest == can_db {
                return Err(
                    "Cannot export to the same file the app is currently using.".to_string()
                );
            }
        }

        let salt_path = db_path.with_file_name("vault.salt").clean();
        let dest_salt = dest_db
            .with_extension(format!(
                "{}.salt",
                dest_db
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("bvda")
            ))
            .clean();

        std::fs::copy(&db_path, &dest_db).map_err(|e| e.to_string())?;
        if salt_path.exists() {
            std::fs::copy(&salt_path, &dest_salt).map_err(|e| e.to_string())?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dest_db, std::fs::Permissions::from_mode(0o600));
            if dest_salt.exists() {
                let _ =
                    std::fs::set_permissions(&dest_salt, std::fs::Permissions::from_mode(0o600));
            }
        }

        Ok(())
    }

    pub async fn export_secure_package(
        &self,
        dest_path: &str,
        password: String,
    ) -> Result<(), String> {
        let dest = Path::new(dest_path).clean();
        if dest.as_os_str().is_empty() {
            return Err("Destination path cannot be empty".to_string());
        }

        let db_path = self.db_path.clean();
        if dest == db_path {
            return Err(
                "Cannot overwrite the active vault database with an export package.".to_string(),
            );
        }

        let engine = self.get_engine()?;
        let secret_pass = SecretString::new(password);
        let package_json = engine
            .export_vault(&secret_pass)
            .await
            .map_err(|e| format!("Export failed: {}", e))?;

        std::fs::write(&dest, package_json)
            .map_err(|e| format!("Failed to write export file: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600));
        }

        Ok(())
    }

    pub async fn import_secure_package(
        &self,
        src_path: &str,
        password: String,
        strategy: ImportStrategy,
    ) -> Result<(), String> {
        let src = Path::new(src_path).clean();
        if !src.exists() {
            return Err("The import file does not exist".to_string());
        }

        let engine = self.get_engine()?;
        let package_json = std::fs::read_to_string(&src)
            .map_err(|e| format!("Failed to read import file: {}", e))?;
        let secret_pass = SecretString::new(password);
        engine
            .import_vault(&package_json, &secret_pass, strategy)
            .await
            .map_err(|e| format!("Import failed: {}", e))
    }

    pub async fn prepare_import_db(&self, src_path: &str) -> Result<(), String> {
        let src = Path::new(src_path).clean();
        if !src.exists() {
            return Err("The source file does not exist".to_string());
        }

        let db_path = self.db_path.clean();
        let is_same_file = src == db_path
            || (src.canonicalize().is_ok()
                && db_path.canonicalize().is_ok()
                && src.canonicalize().unwrap() == db_path.canonicalize().unwrap());

        if is_same_file {
            return Err(
                "Cannot import the same file the app is using. Use 'Export' for backups."
                    .to_string(),
            );
        }

        // Close the pool to release the lock before overwriting
        let engine = {
            let mut engine_lock = self.engine.lock().unwrap();
            engine_lock.take()
        };
        if let Some(e) = engine {
            e.close().await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Delete WAL/SHM files to prevent corruption
        let _ = std::fs::remove_file(db_path.with_extension("bvda-wal"));
        let _ = std::fs::remove_file(db_path.with_extension("bvda-shm"));

        let src_salt = src
            .with_extension(format!(
                "{}.salt",
                src.extension().and_then(|e| e.to_str()).unwrap_or("bvda")
            ))
            .clean();
        let dest_salt = db_path.with_file_name("vault.salt").clean();

        if src_salt.exists() {
            std::fs::copy(&src_salt, &dest_salt)
                .map_err(|e| format!("Error to copy salt: {}", e))?;
        } else {
            let _ = std::fs::remove_file(&dest_salt);
        }

        std::fs::copy(&src, &db_path).map_err(|e| format!("Error to copy file: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600));
            if dest_salt.exists() {
                let _ =
                    std::fs::set_permissions(&dest_salt, std::fs::Permissions::from_mode(0o600));
            }
        }

        Ok(())
    }
}
