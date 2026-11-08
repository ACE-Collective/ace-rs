//! Answering a module's reads of ACE's data (PLAN.md 7.2) without the core, for its tests.
//!
//! `FakeReads` answers each read with the JSON a test gives it for that read's name, keeps every
//! request, and refuses a read it has no answer for as the core refuses an undeclared one (403).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use ace_sdk::reads::{ReadError, Reader};
use serde_json::Value;

/// How a fake read answers.
#[derive(Debug, Clone)]
pub enum FakeAnswer {
    Answer(Value),
    /// The store behind the read is down (503).
    Unavailable,
}

/// A reader that answers from what the test gave it.
#[derive(Debug, Default)]
pub struct FakeReads {
    answers: BTreeMap<&'static str, FakeAnswer>,
    requests: Mutex<Vec<(&'static str, Value)>>,
}

impl FakeReads {
    pub fn new() -> Self {
        FakeReads::default()
    }

    /// Answers read `read` with `answer`.
    pub fn answer(mut self, read: &'static str, answer: Value) -> Self {
        self.answers.insert(read, FakeAnswer::Answer(answer));
        self
    }

    /// Answers read `read` as when its store is down.
    pub fn unavailable(mut self, read: &'static str) -> Self {
        self.answers.insert(read, FakeAnswer::Unavailable);
        self
    }

    /// Every read made, with its request, in order.
    pub fn requests(&self) -> Vec<(&'static str, Value)> {
        self.requests.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

impl Reader for FakeReads {
    fn read<'a>(
        &'a self,
        _task: i64,
        read: &'static str,
        request: Value,
    ) -> Pin<Box<dyn Future<Output = Result<Value, ReadError>> + Send + 'a>> {
        if let Ok(mut requests) = self.requests.lock() {
            requests.push((read, request));
        }
        let answer = match self.answers.get(read) {
            Some(FakeAnswer::Answer(answer)) => Ok(answer.clone()),
            Some(FakeAnswer::Unavailable) => Err(ReadError::Unavailable {
                read,
                source: "503: the store is down".into(),
            }),
            None => Err(ReadError::Refused {
                read,
                status: 403,
                message: format!("the fake has no answer for {read}"),
            }),
        };
        Box::pin(async move { answer })
    }
}
