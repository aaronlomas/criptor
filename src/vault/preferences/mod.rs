// Preferences & settings operations.

use crate::error::CriptorResult;
use crate::storage;
use crate::vault::validation;

impl super::CriptorEngine {
    /// Reads a preference value by key.
    pub async fn get_preference(&self, key: &str) -> CriptorResult<Option<String>> {
        self.check_unlocked()?;
        storage::get_preference(&self.db, key).await
    }

    /// Writes a preference value (insert or update).
    pub async fn set_preference(&self, key: &str, value: &str) -> CriptorResult<()> {
        self.check_unlocked()?;
        validation::validate_string(key, "Preference", validation::MAX_PREF_KEY_LEN, true)?;
        validation::validate_string(
            value,
            "Preference value",
            validation::MAX_PREF_VALUE_LEN,
            false,
        )?;
        storage::set_preference(&self.db, key, value).await
    }

    /// Deletes a preference by key.
    pub async fn delete_preference(&self, key: &str) -> CriptorResult<()> {
        self.check_unlocked()?;
        validation::validate_string(key, "Preference", validation::MAX_PREF_KEY_LEN, true)?;
        storage::delete_preference(&self.db, key).await
    }
}
