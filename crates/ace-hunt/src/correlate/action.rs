//! A correlation's actions (`actions.py`): what happens to an event, and the line each logs.

use serde::Serialize;

use super::Action;
use super::expr::{Scope, render};
use crate::render::Renderer;

/// `ActionResult`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionResult {
    /// filter, stop, discard, alert, log or timeout.
    pub action_type: String,
    pub queue_override: Option<String>,
    pub analysis_mode_override: Option<String>,
}

impl ActionResult {
    pub fn of(action_type: &str) -> ActionResult {
        ActionResult {
            action_type: action_type.to_owned(),
            queue_override: None,
            analysis_mode_override: None,
        }
    }

    /// Whether it ends the event's steps.
    pub fn is_interrupt(&self) -> bool {
        ["filter", "stop", "discard", "alert", "timeout"].contains(&self.action_type.as_str())
    }

    /// Whether it ends the stream.
    pub fn is_stream_interrupt(&self) -> bool {
        ["stop", "discard"].contains(&self.action_type.as_str())
    }
}

/// A log line's level, Python's names for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Level {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl Level {
    /// `getattr(logging, name.upper(), logging.INFO)`.
    pub fn named(name: &str) -> Level {
        match name.to_uppercase().as_str() {
            "DEBUG" => Level::Debug,
            "WARNING" | "WARN" => Level::Warning,
            "ERROR" => Level::Error,
            "CRITICAL" | "FATAL" => Level::Critical,
            _ => Level::Info,
        }
    }
}

/// A line ace3's correlation logs, which ace-rs's caller writes with its own logger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogLine {
    pub level: Level,
    pub message: String,
}

impl LogLine {
    pub fn new(level: Level, message: impl Into<String>) -> LogLine {
        LogLine {
            level,
            message: message.into(),
        }
    }
}

/// `execute_action`: the action's result and what it logs. An action type the schema doesn't
/// know is ace3's ValueError.
pub fn execute_action(
    action: &Action,
    renderer: &Renderer,
    scope: Scope<'_>,
    logs: &mut Vec<LogLine>,
) -> Result<ActionResult, String> {
    let result = match action.kind.as_str() {
        "filter" | "stop" | "discard" | "log" => ActionResult::of(&action.kind),
        "alert" => ActionResult {
            action_type: "alert".to_owned(),
            queue_override: action.queue.clone(),
            analysis_mode_override: action.analysis_mode.clone(),
        },
        other => {
            return Err(format!(
                "unknown action type: {}",
                crate::value::py_repr(other)
            ));
        }
    };
    log_action(action, renderer, scope, logs);
    Ok(result)
}

/// `_log_action`: the rendered `log_message` at `log_level`, or `executed <type> action`; a
/// message that fails to render is a warning of its own, and nothing else.
fn log_action(action: &Action, renderer: &Renderer, scope: Scope<'_>, logs: &mut Vec<LogLine>) {
    let level = Level::named(&action.log_level);
    let message = match &action.log_message {
        Some(template) if !template.is_empty() => match render(renderer, template, scope) {
            Ok(m) => m,
            Err(_) => {
                logs.push(LogLine::new(
                    Level::Warning,
                    format!("failed to render log message template: {template}"),
                ));
                return;
            }
        },
        _ => format!("executed {} action", action.kind),
    };
    logs.push(LogLine::new(level, format!("correlation log: {message}")));
}
