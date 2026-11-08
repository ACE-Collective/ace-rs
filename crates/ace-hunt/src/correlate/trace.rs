//! The record of a correlation run (`saq/collectors/hunter/correlation/trace.py`): each event's
//! path through the logic, step by step, and the stream's resets, timeouts and discard. ace3 keeps
//! it in each correlated alert's details, scoped to the events behind that alert, and the `hunt`
//! router's validation answers with it. The fields serialize in ace3's models' order, a time as
//! ace3 saves one in a root's details (`EVENT_TIME_FORMAT_JSON_TZ`).

use serde::{Serialize, Serializer};

use super::time::Time;

/// `sanitize_value`: each secret's text replaced by `***`, in turn.
pub fn sanitize(value: &str, secrets: &[String]) -> String {
    let mut value = value.to_owned();
    for secret in secrets {
        if !secret.is_empty() && value.contains(secret.as_str()) {
            value = value.replace(secret.as_str(), "***");
        }
    }
    value
}

pub fn sanitize_opt(value: Option<String>, secrets: &[String]) -> Option<String> {
    value.map(|v| sanitize(&v, secrets))
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExpressionTrace {
    pub expression_type: String,
    pub result: bool,
    pub rendered_value: Option<String>,
    pub property_name: Option<String>,
    pub property_value: Option<String>,
    pub compare_value: Option<String>,
    pub sub_expressions: Option<Vec<ExpressionTrace>>,
    pub error: Option<String>,
}

impl ExpressionTrace {
    pub fn new(expression_type: &str, result: bool) -> ExpressionTrace {
        ExpressionTrace {
            expression_type: expression_type.to_owned(),
            result,
            rendered_value: None,
            property_name: None,
            property_value: None,
            compare_value: None,
            sub_expressions: None,
            error: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Branch {
    Execute,
    Else,
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConditionTrace {
    pub trace_type: &'static str,
    pub expression: ExpressionTrace,
    pub branch_taken: Branch,
    pub branch_steps: Vec<StepTrace>,
    pub error: Option<String>,
}

/// A time as ace3 saves one in an alert's details.
fn opt_time<S: Serializer>(t: &Option<Time>, s: S) -> Result<S::Ok, S::Error> {
    match t {
        Some(t) => s.serialize_str(&t.details_format()),
        None => s.serialize_none(),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TransformTrace {
    pub trace_type: &'static str,
    pub transform_type: String,
    pub method: String,
    pub command_type: String,
    pub rendered_command: Option<String>,
    pub property_name: Option<String>,
    pub property_value: Option<String>,
    pub result_count: Option<usize>,
    pub merge_dropped: Option<usize>,
    #[serde(serialize_with = "opt_time")]
    pub query_start_time: Option<Time>,
    #[serde(serialize_with = "opt_time")]
    pub query_end_time: Option<Time>,
    pub query_time_spec: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ActionTrace {
    pub trace_type: &'static str,
    pub action_type: String,
    pub rendered_log_message: Option<String>,
    pub is_interrupt: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum StepKindTrace {
    Condition(ConditionTrace),
    Transform(TransformTrace),
    Action(ActionTrace),
}

impl StepKindTrace {
    pub fn trace_type(&self) -> &'static str {
        match self {
            StepKindTrace::Condition(_) => "condition",
            StepKindTrace::Transform(_) => "transform",
            StepKindTrace::Action(_) => "action",
        }
    }

    pub fn condition(&self) -> Option<&ConditionTrace> {
        match self {
            StepKindTrace::Condition(c) => Some(c),
            _ => None,
        }
    }

    pub fn transform(&self) -> Option<&TransformTrace> {
        match self {
            StepKindTrace::Transform(t) => Some(t),
            _ => None,
        }
    }

    pub fn action(&self) -> Option<&ActionTrace> {
        match self {
            StepKindTrace::Action(a) => Some(a),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StepTrace {
    pub description: Option<String>,
    pub step: StepKindTrace,
    /// Wall time, inclusive of a condition's branch.
    pub duration_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EventTrace {
    pub event_index: usize,
    pub steps: Vec<StepTrace>,
    /// alert, filter, stop, discard, timeout, error or stream_reset.
    pub outcome: String,
    pub duration_ms: Option<f64>,
    pub summary: Option<String>,
    pub events_position: Option<usize>,
}

impl EventTrace {
    pub fn new(event_index: usize) -> EventTrace {
        EventTrace {
            event_index,
            steps: Vec::new(),
            outcome: "alert".to_owned(),
            duration_ms: None,
            summary: None,
            events_position: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StreamEvent {
    /// stream_reset, timeout or discard.
    pub event_type: String,
    pub at_event_index: Option<usize>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CorrelationTrace {
    pub event_traces: Vec<EventTrace>,
    pub stream_events: Vec<StreamEvent>,
}
