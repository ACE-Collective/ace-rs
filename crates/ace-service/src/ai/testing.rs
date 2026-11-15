//! Backends that answer canned rows, and limiters that refuse: ace3's `saq/ai_query/backends/testing.py`,
//! which it ships so the API can be built and exercised with no data source. The `extras` drive the
//! failures the routes' contract must surface. `ace serve` offers the two backends as the types `fake`
//! and `fake_unwindowed`, for a site to try a key and its limits before a real backend.

use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::limiter::{AiLimiter, LimitError, Slot};
use super::{AiFuture, AiLimits, AiQueryBackend, AiQueryError, AiQueryRequest, AiQueryResult};

/// The rows every query answers with: ace3's `FAKE_ROWS`.
pub fn fake_rows() -> Vec<Map<String, Value>> {
    [
        json!({"_time": "2026-01-01T00:00:00Z", "host": "host-a", "value": "1"}),
        json!({"_time": "2026-01-01T00:01:00Z", "host": "host-b", "value": "2"}),
    ]
    .into_iter()
    .filter_map(|row| row.as_object().cloned())
    .collect()
}

/// ace3's `FakeQueryExtras`.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
struct FakeExtras {
    /// `truncated`, `rejected`, `backend_error` or `sleep`.
    simulate: Option<String>,
    sleep_seconds: f64,
    error_status_code: Option<u16>,
}

impl FakeExtras {
    fn parse(extras: &Map<String, Value>) -> Result<FakeExtras, String> {
        let extras: FakeExtras =
            serde_json::from_value(Value::Object(extras.clone())).map_err(|e| e.to_string())?;
        if !(0.0..=3600.0).contains(&extras.sleep_seconds) {
            return Err("sleep_seconds is 0 to 3600".to_owned());
        }
        Ok(extras)
    }
}

/// ace3's `FakeAIQueryBackend`, and with `windowed` false its `FakeUnwindowedAIQueryBackend`.
#[derive(Debug)]
pub struct FakeBackend {
    windowed: bool,
    /// The last request `execute` saw.
    last: Mutex<Option<AiQueryRequest>>,
}

impl FakeBackend {
    pub fn new() -> Self {
        FakeBackend {
            windowed: true,
            last: Mutex::new(None),
        }
    }

    pub fn unwindowed() -> Self {
        FakeBackend {
            windowed: false,
            last: Mutex::new(None),
        }
    }

    pub fn last_request(&self) -> Option<AiQueryRequest> {
        self.last.lock().ok().and_then(|last| last.clone())
    }
}

impl Default for FakeBackend {
    fn default() -> Self {
        FakeBackend::new()
    }
}

impl AiQueryBackend for FakeBackend {
    fn windowed(&self) -> bool {
        self.windowed
    }

    fn extras_schema(&self) -> Option<Value> {
        Some(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "simulate": {"type": ["string", "null"], "enum": ["truncated", "rejected", "backend_error", "sleep", null]},
                "sleep_seconds": {"type": "number", "minimum": 0, "maximum": 3600},
                "error_status_code": {"type": ["integer", "null"]},
            },
        }))
    }

    fn check_extras(&self, extras: &Map<String, Value>) -> Result<(), String> {
        FakeExtras::parse(extras).map(|_| ())
    }

    fn describe(&self) -> Map<String, Value> {
        json!({
            "query_language": "fake",
            "time_semantics": "in-band",
            "notes": "test backend returning canned rows",
        })
        .as_object()
        .cloned()
        .unwrap_or_default()
    }

    fn validate(&self, request: &AiQueryRequest, _limits: &AiLimits) -> Result<(), String> {
        if request.query.trim().is_empty() {
            return Err("query must not be empty".to_owned());
        }
        if self.windowed && request.start_time >= request.end_time {
            return Err("start_time must be before end_time".to_owned());
        }
        let extras = FakeExtras::parse(&request.extras)?;
        if extras.simulate.as_deref() == Some("rejected") {
            return Err("simulated rejection".to_owned());
        }
        Ok(())
    }

    fn execute<'a>(
        &'a self,
        request: &'a AiQueryRequest,
        _limits: &'a AiLimits,
    ) -> AiFuture<'a, Result<AiQueryResult, AiQueryError>> {
        Box::pin(async move {
            if let Ok(mut last) = self.last.lock() {
                *last = Some(request.clone());
            }
            let extras = FakeExtras::parse(&request.extras).map_err(AiQueryError::Rejected)?;
            let simulate = extras.simulate.as_deref();
            if simulate == Some("backend_error") {
                return Err(AiQueryError::Backend {
                    status: extras.error_status_code.unwrap_or(502),
                    reason: "simulated backend failure".to_owned(),
                });
            }
            if simulate == Some("sleep") {
                tokio::time::sleep(Duration::from_secs_f64(extras.sleep_seconds)).await;
            }
            let mut rows = fake_rows();
            let truncated = simulate == Some("truncated");
            if truncated {
                rows.truncate(1);
            }
            Ok(AiQueryResult {
                rows,
                truncated,
                truncation_reason: truncated.then(|| "backend_cap".to_owned()),
                window_start: request.start_time,
                window_end: request.end_time,
                duration_ms: (extras.sleep_seconds * 1000.0) as u64,
                meta: json!({"fake": true})
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            })
        })
    }
}

/// A limiter that does as it's told, where ace3's tests patch the limiter: it refuses a slot or a
/// request with what it was given, or can't be reached, and counts the requests it was asked to
/// count.
#[derive(Debug, Default)]
pub struct ScriptedLimiter {
    pub slot: Option<LimitError>,
    pub request: Option<LimitError>,
    /// The buckets `check_request` was called for, in order.
    pub checked: Mutex<Vec<String>>,
    /// How many slots were given back.
    pub released: Mutex<usize>,
}

impl AiLimiter for ScriptedLimiter {
    fn acquire<'a>(
        &'a self,
        bucket: &'a str,
        _limits: &'a AiLimits,
    ) -> AiFuture<'a, Result<Slot, LimitError>> {
        Box::pin(async move {
            match &self.slot {
                Some(error) => Err(error.clone()),
                None => Ok(Slot {
                    bucket: bucket.to_owned(),
                    token: uuid::Uuid::new_v4(),
                }),
            }
        })
    }

    fn check_request<'a>(
        &'a self,
        bucket: &'a str,
        _limits: &'a AiLimits,
    ) -> AiFuture<'a, Result<(), LimitError>> {
        Box::pin(async move {
            if let Ok(mut checked) = self.checked.lock() {
                checked.push(bucket.to_owned());
            }
            match &self.request {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        })
    }

    fn release(&self, _slot: Slot) -> AiFuture<'_, ()> {
        Box::pin(async move {
            if let Ok(mut released) = self.released.lock() {
                *released += 1;
            }
        })
    }
}
