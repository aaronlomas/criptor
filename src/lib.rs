pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod audit;
pub mod auth;
pub mod client;
pub mod crypto;
pub mod error;
pub mod security;
pub mod storage;
pub mod vault;

#[cfg(test)]
mod tests;

pub use client::CriptorClient;
pub use crypto::secret::{SecretKey, SecretString};
pub use error::{CriptorError, CriptorResult};
pub use storage::models::{Account, Document, Pin};
pub use vault::CriptorEngine;
pub use vault::MasterKey;

/// Applies OS-level anti-forensic protections to the current process.
pub fn harden_process() {
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
            eprintln!("Warning: Failed to disable core dumps via PR_SET_DUMPABLE");
        }
    }

    #[cfg(target_os = "windows")]
    unsafe {
        // SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX
        // Prevents the system from displaying critical-error-handler and Windows Error Reporting dialogs.
        use windows_sys::Win32::System::Diagnostics::Debug::{
            SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
        };
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    }
}
