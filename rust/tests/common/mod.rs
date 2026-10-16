#![allow(dead_code)]

use std::path::PathBuf;

use serde_json::Value;

/// Loads `testvectors/<rel>` from the hpqc repository. Returns `None` when the
/// directory is absent, as in a published crate.
pub fn load(rel: &str) -> Option<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(rel);
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("skipping: {} not found", path.display());
        return None;
    };
    Some(serde_json::from_str(&text).expect("valid json"))
}

pub fn cases(v: &Value) -> &Vec<Value> {
    v.get("vectors")
        .or_else(|| v.get("cases"))
        .and_then(Value::as_array)
        .expect("vector list")
}

pub fn hex(v: &Value, field: &str) -> Vec<u8> {
    ::hex::decode(
        v[field]
            .as_str()
            .unwrap_or_else(|| panic!("missing {field}")),
    )
    .unwrap()
}

pub fn str<'a>(v: &'a Value, field: &str) -> &'a str {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("missing {field}"))
}
