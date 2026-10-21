//! # Security Exposure Scanner
//!
//! Provides static inspection of local surfaces to identify exposed credentials,
//! unencrypted keys, and leaked configurations.

pub mod pass;

use std::time::Duration;

/// Category of surface where sensitive data was discovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExposureSource {
    Environment,
    TempFile,
    ShellHistory,
}

impl ExposureSource {
    /// Formats the source as a short uppercase tag for terminal output.
    pub fn tag(&self) -> &'static str {
        match self {
            ExposureSource::Environment => "ENV",
            ExposureSource::TempFile => "TEMP",
            ExposureSource::ShellHistory => "HISTORY",
        }
    }
}

/// A single detected sensitive credential exposure.
#[derive(Debug, Clone)]
pub struct ExposureHit {
    /// Source category where the exposure occurred.
    pub source: ExposureSource,
    /// Location identifier such as environment variable name or file path with line number.
    pub location: String,
    /// Descriptive category of the pattern matched.
    pub pattern_name: String,
    /// Redacted representation of the secret value to avoid displaying sensitive material.
    pub redacted_value: String,
    /// Actionable mitigation advice.
    pub recommendation: String,
}

/// Aggregated report of an exposure scan.
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// List of detected exposures.
    pub hits: Vec<ExposureHit>,
    /// Number of distinct sources inspected during the scan.
    pub sources_checked: usize,
    /// Time elapsed during the scan.
    pub duration: Duration,
}

impl ScanReport {
    /// Indicates whether no exposures were detected during the scan.
    pub fn is_clean(&self) -> bool {
        self.hits.is_empty()
    }
}
