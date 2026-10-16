//! The v2 storage body of a box record.

use tinybox_core::{BoxInfo, BoxSpec, BoxState, Error, Result};

#[cfg(test)]
#[path = "record_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
