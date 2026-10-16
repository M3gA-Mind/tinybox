use super::*;
use serde_json::json;
use tinystoragedrivers_core::schema::{Item, MigrateOptions, Registry};
use tinystoragedrivers_core::{
    DocumentStore, MemoryStorage, Precondition, Scope, ScopedStorage, StorageBackend,
};

/// A box as the v1 store wrote it: `BoxInfo` serialized by serde, keyed by id.
fn v1_box() -> Value {
    json!({
        "id": "build-1",
        "state": "Ready",
        "spec": {
            "runner": "local/passthrough",
            "workspace": "local/passthrough",
            "source": {"LocalDir": "/srv/work"},
            "resources": {
                "cpu_millis": 2000,
                "memory_bytes": 2_147_483_648_u64,
                "pids_max": 512,
                "disk_bytes": 8_589_934_592_u64,
            },
            "lifecycle": {"Ephemeral": {"ttl": {"secs": 3600, "nanos": 0}}},
            "network": {"Allowlist": {"hosts": ["example.test"], "ports": [443]}},
            "ports": [{"guest": 80, "host": null}],
            "env": {"KEY": "value"},
        },
        "created_at": {"secs_since_epoch": 1_700_000_000_u64, "nanos_since_epoch": 5_000_000_u32},
    })
}

fn v1_jail_index() -> Value {
    json!({
        "schema_version": 1,
        "records": {
            "j1": {
                "id": "j1",
                "label": "build",
                "dir": "/srv/j1",
                "backend_at_create": "landlock",
                "created_at_unix": 1_700_000_000_u64,
                "updated_at_unix": 1_700_000_060_u64,
                "notes": "keep",
            },
        },
    })
}

async fn migrated(
    seed: impl FnOnce(Arc<dyn DocumentStore>) -> futures_like::Seed,
) -> ScopedStorage {
    let _ = seed;
    unreachable!()
}

mod futures_like {
    pub(super) type Seed = ();
}
