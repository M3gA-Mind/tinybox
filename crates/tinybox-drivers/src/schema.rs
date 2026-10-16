//! What tinybox stores, as a [`Schema`] the host composes.
//!
//! Owner `box`, both collections at body version 2 in the module scope:
//!
//! | v1 | v2 |
//! |---|---|
//! | `tinybox_boxes` | [`BOX_COLLECTION`] (`box.boxes`) |
//! | `tinybox_jail_index` | [`JAIL_INDEX_COLLECTION`] (`box.jail_index`) |
//!
//! A host grants the module exactly these items (`ScopeClass::Module`), so the
//! grant is derived from [`storage_schema`] rather than restated. The steps
//! bring v1 rows forward when the host runs `Registry::migrate`.

use serde_json::Value;
use tinybox_core::BoxInfo;
use tinystoragedrivers_core::schema::{
    Owner, Schema, ScopeClass, SourceRecord, Step, TargetRecord,
};
use tinystoragedrivers_core::{Key, Result, StorageError};

use crate::index_body;
use crate::record::BoxRecord;

/// The collection that holds one document per box, keyed by box id.
pub const BOX_COLLECTION: &str = "box.boxes";

/// The collection that holds one index document per jail registry.
pub const JAIL_INDEX_COLLECTION: &str = "box.jail_index";

/// The v1 name of [`BOX_COLLECTION`].
const V1_BOX_COLLECTION: &str = "tinybox_boxes";

/// The v1 name of [`JAIL_INDEX_COLLECTION`].
const V1_JAIL_INDEX_COLLECTION: &str = "tinybox_jail_index";

/// The body version both collections are declared at.
pub(crate) const BODY_VERSION: u32 = 2;

/// Everything tinybox stores, with the v1 to v2 migration steps.
///
/// # Panics
///
/// Never in practice: the owner name is a constant that satisfies the owner
/// grammar.
#[must_use]
pub fn storage_schema() -> Schema {
    #[allow(clippy::expect_used, reason = "a constant that satisfies the grammar")]
    let owner = Owner::new("box").expect("`box` is a valid owner");
    Schema::new(owner)
        .collection(BOX_COLLECTION, BODY_VERSION, ScopeClass::Module)
        .collection(JAIL_INDEX_COLLECTION, BODY_VERSION, ScopeClass::Module)
        .step(
            Step::new("rename_boxes", BOX_COLLECTION, 1, BODY_VERSION, |batch| {
                batch.into_iter().map(box_to_v2).collect()
            })
            .source(V1_BOX_COLLECTION),
        )
        .step(
            Step::new(
                "rename_jail_index",
                JAIL_INDEX_COLLECTION,
                1,
                BODY_VERSION,
                |batch| batch.into_iter().map(jail_index_to_v2).collect(),
            )
            .source(V1_JAIL_INDEX_COLLECTION),
        )
}

/// A v1 box row (a serialized `BoxInfo`) as a v2 record under the same id.
fn box_to_v2(source: SourceRecord) -> Result<TargetRecord> {
    let id = Key::of([source.id.as_str()])?;
    let info: BoxInfo = serde_json::from_value(source.body).map_err(|error| {
        StorageError::serialization(format!("v1 box `{}` does not decode: {error}", source.id))
    })?;
    let record = BoxRecord::try_from(&info)
        .map_err(|error| StorageError::serialization(error.to_string()))?;
    Ok(TargetRecord::new(
        BOX_COLLECTION,
        id.as_str(),
        serde_json::to_value(record)?,
    ))
}

/// A v1 jail index row as a v2 record under the same id.
fn jail_index_to_v2(source: SourceRecord) -> Result<TargetRecord> {
    let id = Key::of([source.id.as_str()])?;
    let body: Value = index_body::to_body(source.body).map_err(|error| {
        StorageError::serialization(format!("v1 jail index `{}`: {error}", source.id))
    })?;
    Ok(TargetRecord::new(JAIL_INDEX_COLLECTION, id.as_str(), body))
}

#[cfg(test)]
#[path = "schema_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
