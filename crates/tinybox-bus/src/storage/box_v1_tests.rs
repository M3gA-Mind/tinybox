use super::*;

fn v1() -> Value {
    json!({
        "id": "b",
        "state": "Paused",
        "spec": {
            "runner": {"host": "local", "sandbox": "passthrough"},
            "workspace": {"host": "local", "sandbox": "passthrough"},
            "source": {"GitRepo": {"url": "https://x.test/r", "rev": "main"}},
            "resources": {"cpu_millis": 1, "memory_bytes": 2, "pids_max": 3, "disk_bytes": 4},
            "lifecycle": {"Persistent": {"autosnapshot": {"secs": 5, "nanos": 7_000_000}}},
            "network": "Open",
            "env": {},
        },
        "created_at": {"secs_since_epoch": 2, "nanos_since_epoch": 3_000_000},
    })
}

#[test]
fn every_variant_takes_its_v2_tagged_form() {
    let body = to_body(v1()).expect("decodes");
    assert_eq!(body["state"], "paused");
    assert_eq!(body["created_ms"], 2003);
    assert_eq!(
        body["spec"]["source"],
        json!({"kind": "git_repo", "url": "https://x.test/r", "rev": "main"})
    );
    assert_eq!(
        body["spec"]["lifecycle"],
        json!({"kind": "persistent", "autosnapshot_ms": 5007})
    );
    assert_eq!(body["spec"]["network"], json!({"kind": "open"}));
    assert_eq!(body["spec"]["ports"], json!([]));
    assert!(body.get("id").is_none(), "the id is the document id");
}

#[test]
fn a_persistent_box_without_autosnapshot_keeps_it_null() {
    let mut old = v1();
    old["spec"]["lifecycle"] = json!({"Persistent": {}});
    let body = to_body(old).expect("decodes");
    assert_eq!(body["spec"]["lifecycle"]["autosnapshot_ms"], Value::Null);
}

#[test]
fn an_unknown_state_is_refused() {
    let mut old = v1();
    old["state"] = json!("Levitating");
    to_body(old).expect_err("unknown state");
}
