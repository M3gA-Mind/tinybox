//! tinybox on the host's `tinystoragedrivers` ports.
//!
//! The backend (`SQLite`, `MongoDB`, files, memory) and the tenant scope are the
//! host's choice, made when it builds the [`DocumentStore`] handle. Nothing here
//! names a database.
//!
//! - [`DocumentBoxStore`]: box records as documents, behind
//!   [`tinybox_core::Store`].
//! - [`DocumentIndexStore`]: the jail registry's index as one document, behind
//!   [`tinybox_jail::IndexStore`].
//!
//! Both traits are synchronous, so each store owns a [`Blocking`] bridge that
//! runs the port's futures on a dedicated runtime thread. That works from inside
//! or outside a tokio runtime.
//!
//! [`DocumentStore`]: tinystoragedrivers_core::DocumentStore
//! [`Blocking`]: tinystoragedrivers_core::Blocking

mod box_store;
mod index_store;

pub use box_store::{BOX_COLLECTION, DocumentBoxStore};
pub use index_store::{DocumentIndexStore, JAIL_INDEX_COLLECTION};

#[cfg(test)]
#[path = "faulty_tests.rs"]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod faulty;
