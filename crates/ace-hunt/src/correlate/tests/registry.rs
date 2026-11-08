//! `test_registry.py`: 5 cases. ace3's registry is a module global the fixture clears; ace4's is a
//! value each run is handed.

use std::sync::Arc;

use serde_json::json;

use super::TestSource;
use crate::correlate::source::{QuerySource, Sources};

fn source() -> Arc<dyn QuerySource> {
    TestSource::new(json!([{"result": "test"}]))
}

#[test]
fn test_register_and_get() {
    let s = source();
    let mut sources = Sources::new();
    sources.register("test", s.clone());
    assert!(Arc::ptr_eq(sources.get("test").expect("registered"), &s));
}

#[test]
fn test_get_unregistered_raises() {
    let sources = Sources::new();
    assert!(matches!(sources.get("nonexistent"), Err(e) if e.contains("not registered")));
}

#[test]
fn test_overwrite_registration() {
    let (s1, s2) = (source(), source());
    let mut sources = Sources::new();
    assert!(!sources.register("test", s1));
    // ace3 warns of the overwrite; register says it replaced one
    assert!(sources.register("test", s2.clone()));
    assert!(Arc::ptr_eq(sources.get("test").expect("registered"), &s2));
}

#[test]
fn test_clear_sources() {
    let mut sources = Sources::new();
    sources.register("test", source());
    sources.clear();
    assert!(sources.names().is_empty());
}

#[test]
fn test_get_registered_sources() {
    let s = source();
    let mut sources = Sources::new();
    sources.register("src1", s.clone());
    sources.register("src2", s);
    let names = sources.names();
    assert!(names.contains(&"src1"));
    assert!(names.contains(&"src2"));
}
