// ─────────────────────────────────────────────────────────────────────────────
// Persistence layer
//
// This layer is intentionally crypto-agnostic: every sensitive column stores
// ciphertext produced by the `vault` layer. Each domain lives in its own module
// and its items are re-exported here so callers keep using `storage::<fn>`.
// ─────────────────────────────────────────────────────────────────────────────

pub mod models;

pub mod account;
pub mod audit;
pub mod document;
pub mod group;
pub mod pin;
pub mod preference;
pub mod schema;

pub use account::*;
pub use audit::*;
pub use document::*;
pub use group::*;
pub use pin::*;
pub use preference::*;
pub use schema::*;

#[cfg(test)]
mod tests;
