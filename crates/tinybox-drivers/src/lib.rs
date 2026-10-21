//! tinybox on the host's `tinystoragedrivers` ports.
//!
//! The backend and scope are supplied by the host through v2 storage ports.
//!
//! - [`DocumentBoxStore`]: box records as documents, behind
//!   [`tinybox_core::Store`].
//! - [`DocumentIndexStore`]: the jail registry's index as one document, behind
//!   [`tinybox_jail::IndexStore`].
//!
//! - [`collections`]: the pure declarations a host ensures before granting
//!   access. This crate runs its own legacy-row migrations when a store opens.
//!
//! Both traits are synchronous, so each store owns a [`Blocking`] bridge that
//! runs the port's futures on a dedicated runtime thread. That works from inside
//! or outside a tokio runtime.
//!
//! [`DocumentStore`]: tinystoragedrivers_api::DocumentStore
mod box_store;
mod blocking;
mod index_store;
mod migrations;
mod record;
mod repo;
mod template_store;

pub use box_store::DocumentBoxStore;
pub use index_store::DocumentIndexStore;
pub use template_store::DocumentTemplateStore;
pub use tinybox_bus::storage::{
    BODY_VERSION, BOX_COLLECTION, JAIL_INDEX_COLLECTION, MIGRATIONS_COLLECTION,
    TEMPLATE_COLLECTION, collections,
};
/// Ensure TinyBox's owned collections and apply all known row migrations.
pub use migrations::prepare as prepare_storage;

#[cfg(test)]
#[path = "faulty_tests.rs"]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod faulty;
