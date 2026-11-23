//! The correlation engine (`engine.py`): each event of a search's rows through a hunt's
//! `correlate` logic, step by step, deciding which become alerts.
//!
//! An event ends at the first step that interrupts it: `filter` drops it, `alert` keeps it (with
//! its queue and analysis mode), `stop` keeps the ones before it and ends the stream, and `discard`
//! drops the whole run. An event that runs out of steps is an alert. A stream transform replaces
//! the stream and starts it again from its first event at the step after the transform. A step that
//! fails makes its event an alert, its trace saying why, so a broken hunt alerts rather than hides
//! its events; what ace3 doesn't catch (a pattern that doesn't compile, a sub-expression that
//! isn't one) ends the run, as [`EngineError`].
//!
//! **Bounds.** ace3's run is bounded by the correlate `timeout` (15 minutes unless the hunt says),
//! checked before each step, and each command by its own `timeout`, which a query source and a
//! custom type honour. ace-rs keeps both and adds [`Limits`]: every template is bounded by the
//! renderer's fuel, output and items (6.3); a command's output, all commands' output in one run and
//! the events a stream transform makes are bounded, and past a bound the step fails as any step
//! error does; and the text the trace keeps of one rendered value, command or error is bounded,
//! the rest replaced by a marker. A stop asked of the hunter ends the run between steps and
//! inside a query.

use std::collections::{BTreeMap, HashMap};
use std::time::Instant;

use chrono::{DateTime, TimeDelta, Utc};
use serde_json::Value as Json;

use super::action::{ActionResult, Level, LogLine, execute_action};
use super::cache::{Cache, RecordedQuery, Recorder};
use super::command::{Call, CommandTypes, timespec};
use super::expr::{Evaluator, Scope, render};
use super::source::Sources;
use super::time::Time;
use super::trace::{
    ActionTrace, Branch, ConditionTrace, CorrelationTrace, EventTrace, StepKindTrace, StepTrace,
    StreamEvent, TransformTrace, sanitize, sanitize_opt,
};
use super::transform::{Applied, TransformError, apply};
use super::{Action, Condition, Correlate, PredefinedCommand, Step, StepKind, Transform};
use crate::query::schedule::timedelta_str;
use crate::render::Renderer;
use crate::value::{Map, Value};

/// Why a correlation ended without a result.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineError {
    /// What ace3 raises out of its engine, which fails the hunt's run.
    #[error("{0}")]
    Raised(String),
    /// The hunter was asked to stop.
    #[error("the correlation was stopped")]
    Stopped,
}

/// ace-rs's bounds on one run, beyond the correlate timeout and the renderer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The bytes one command may output.
    pub command_output_bytes: usize,
    /// The bytes all of a run's commands may output.
    pub run_output_bytes: usize,
    /// The events a stream transform may make.
    pub stream_events: usize,
    /// The bytes the trace keeps of one text.
    pub trace_text_bytes: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            command_output_bytes: 16 << 20,
            run_output_bytes: 128 << 20,
            stream_events: 10_000,
            trace_text_bytes: 64 << 10,
        }
    }
}

/// What a run uses that isn't the hunt's: where its queries go, the custom command types, the
/// cache, the secrets to scrub from its output and trace, its clock and whether it's to stop.
pub struct Runtime<'a> {
    pub renderer: &'a Renderer,
    pub sources: &'a Sources,
    pub command_types: &'a CommandTypes,
    pub cache: &'a dyn Cache,
    /// Each secret's text, scrubbed from what a run records. No template can read them.
    pub secrets: &'a [String],
    pub clock: &'a (dyn Fn() -> DateTime<Utc> + Sync),
    pub stopped: &'a (dyn Fn() -> bool + Sync),
    pub limits: Limits,
}

/// The hunt run a correlation is part of.
#[derive(Debug, Clone)]
pub struct HuntRun {
    /// The window the hunt searched: a stream transform's time range is anchored to it, `before`
    /// before its start and `after` after its end.
    pub start: Time,
    /// None for a zero-width window at `start`.
    pub end: Option<Time>,
    /// The hunt's type, such as `splunk`, the stream's first source.
    pub source_type: Option<String>,
    pub name: Option<String>,
    pub uuid: Option<String>,
    /// Saved query results to replay, the validator's `correlate_results` queries.
    pub replay: Vec<Json>,
}

impl HuntRun {
    pub fn at(start: DateTime<Utc>) -> HuntRun {
        HuntRun {
            start: Time::from(start),
            end: None,
            source_type: None,
            name: None,
            uuid: None,
            replay: Vec::new(),
        }
    }
}

/// `CorrelationResult`.
#[derive(Debug, Clone, Default)]
pub struct Correlated {
    /// The events that alert, in order.
    pub events: Vec<Map>,
    /// Each alerting event's action by its index in the stream it was in.
    pub event_actions: BTreeMap<usize, ActionResult>,
    /// The stream index of each of `events`, which its trace has.
    pub origins: Vec<usize>,
    pub discarded: bool,
    pub trace: CorrelationTrace,
    /// Every rendered query the run asked, with its rows, for the validator to save.
    pub captured: Vec<RecordedQuery>,
    /// What ace3 would have logged, for the caller's logger.
    pub logs: Vec<LogLine>,
}

/// How a step left its event other than by finishing.
pub(crate) enum Flow {
    /// A step failed, its trace already recorded: the event alerts.
    Step,
    /// A stream transform made a new stream, to resume at this step.
    Reset(Vec<Map>, usize),
    Run(EngineError),
}

impl From<EngineError> for Flow {
    fn from(e: EngineError) -> Flow {
        Flow::Run(e)
    }
}

/// `CorrelationEngine`.
pub struct Engine<'a> {
    pub(crate) rt: &'a Runtime<'a>,
    pub(crate) config: &'a Correlate,
    pub(crate) predefined: &'a [PredefinedCommand],
    pub(crate) hunt_start: Time,
    pub(crate) hunt_end: Time,
    pub(crate) hunt_source_type: Option<String>,
    pub(crate) current_source: Option<String>,
    pub(crate) hunt_name: Option<String>,
    pub(crate) hunt_uuid: Option<String>,
    /// The correlate timeout.
    pub timeout: TimeDelta,
    pub(crate) stream_cache: HashMap<String, String>,
    pub(crate) recorder: Recorder,
    pub(crate) logs: Vec<LogLine>,
    pub(crate) evaluator: Evaluator<'a>,
    pub(crate) output_bytes: usize,
}

const MAX_REPR: usize = 200;

/// `_truncate_repr`.
fn truncate_repr(value: Option<&Value>) -> String {
    let s = match value {
        Some(v) => crate::render::py::repr(&crate::render::py::to_template(v)),
        None => "None".to_owned(),
    };
    if s.chars().count() > MAX_REPR {
        s.chars().take(MAX_REPR).collect::<String>() + "..."
    } else {
        s
    }
}

/// Python's `str.splitlines()`.
pub fn splitlines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let breaks = matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if breaks {
            out.push(&text[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r'
                && let Some(&(j, '\n')) = chars.peek()
            {
                chars.next();
                end = j + 1;
            }
            start = end;
        }
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

fn ms(t0: Instant) -> Option<f64> {
    Some(t0.elapsed().as_secs_f64() * 1000.0)
}

impl<'a> Engine<'a> {
    pub fn new(
        rt: &'a Runtime<'a>,
        config: &'a Correlate,
        predefined: &'a [PredefinedCommand],
        hunt: HuntRun,
    ) -> Engine<'a> {
        Engine {
            rt,
            config,
            predefined,
            hunt_start: hunt.start,
            hunt_end: hunt.end.unwrap_or(hunt.start),
            current_source: hunt.source_type.clone(),
            hunt_source_type: hunt.source_type,
            hunt_name: hunt.name,
            hunt_uuid: hunt.uuid,
            timeout: timespec(&config.timeout).unwrap_or(TimeDelta::minutes(15)),
            stream_cache: HashMap::new(),
            recorder: Recorder::new(&hunt.replay),
            logs: Vec::new(),
            evaluator: Evaluator::new(rt.renderer),
            output_bytes: 0,
        }
    }

    pub(crate) fn log(&mut self, level: Level, message: String) {
        self.logs.push(LogLine::new(level, message));
    }

    pub(crate) fn log_warning(&mut self, message: String) {
        self.log(Level::Warning, message);
    }

    fn label(&self) -> String {
        match (&self.hunt_name, &self.hunt_uuid) {
            (Some(n), Some(u)) => format!("hunt {n} (uuid={u})"),
            (Some(n), None) => format!("hunt {n}"),
            (None, Some(u)) => format!("hunt uuid={u}"),
            (None, None) => "correlate hunt".to_owned(),
        }
    }

    fn elapsed(&self, start: DateTime<Utc>) -> TimeDelta {
        (self.rt.clock)() - start
    }

    /// `execute`: the run over `events`.
    pub fn execute(&mut self, events: Vec<Map>) -> Result<Correlated, EngineError> {
        self.current_source = self.hunt_source_type.clone();
        let mut events = events;
        let mut result = Correlated::default();
        let mut trace = CorrelationTrace::default();
        let start = (self.rt.clock)();
        let mut alerts: Vec<usize> = Vec::new();
        let mut index = 0;
        let mut first_step = 0;
        while index < events.len() {
            self.check_stop()?;
            let elapsed = self.elapsed(start);
            if elapsed >= self.timeout {
                let message = format!(
                    "correlation timeout reached after {} for {}, remaining events will fall through to alert",
                    timedelta_str(elapsed),
                    self.label()
                );
                self.log_warning(message);
                trace.stream_events.push(StreamEvent {
                    event_type: "timeout".to_owned(),
                    at_event_index: Some(index),
                    detail: Some(format!("timeout after {}", timedelta_str(elapsed))),
                });
                for i in index..events.len() {
                    alerts.push(i);
                    result.event_actions.insert(i, ActionResult::of("alert"));
                    let mut et = EventTrace::new(i);
                    et.outcome = "timeout".to_owned();
                    trace.event_traces.push(et);
                }
                break;
            }
            let mut et = EventTrace::new(index);
            let t0 = Instant::now();
            let config = self.config;
            let flow = self.steps(
                &config.logic,
                &mut events,
                index,
                start,
                first_step,
                &mut et.steps,
            );
            et.duration_ms = ms(t0);
            let action = match flow {
                Ok(action) => action,
                Err(Flow::Reset(stream, resume)) => {
                    trace.stream_events.push(StreamEvent {
                        event_type: "stream_reset".to_owned(),
                        at_event_index: Some(index),
                        detail: Some(format!(
                            "stream reset to {} events, resuming at step {resume}",
                            stream.len()
                        )),
                    });
                    events = stream;
                    index = 0;
                    first_step = resume;
                    alerts.clear();
                    result.event_actions.clear();
                    et.outcome = "stream_reset".to_owned();
                    trace.event_traces = vec![et];
                    continue;
                }
                Err(Flow::Step) => {
                    et.outcome = "error".to_owned();
                    alerts.push(index);
                    result
                        .event_actions
                        .insert(index, ActionResult::of("alert"));
                    trace.event_traces.push(et);
                    index += 1;
                    continue;
                }
                Err(Flow::Run(e)) => return Err(e),
            };
            let action = action.unwrap_or_else(|| ActionResult::of("alert"));
            match action.action_type.as_str() {
                "alert" => {
                    alerts.push(index);
                    result.event_actions.insert(index, action);
                    et.outcome = "alert".to_owned();
                }
                "filter" => et.outcome = "filter".to_owned(),
                "stop" => {
                    et.outcome = "stop".to_owned();
                    trace.event_traces.push(et);
                    break;
                }
                "discard" => {
                    et.outcome = "discard".to_owned();
                    trace.event_traces.push(et);
                    trace.stream_events.push(StreamEvent {
                        event_type: "discard".to_owned(),
                        at_event_index: Some(index),
                        detail: None,
                    });
                    result.discarded = true;
                    result.trace = trace;
                    return Ok(self.finish(result));
                }
                "log" => {
                    alerts.push(index);
                    result
                        .event_actions
                        .insert(index, ActionResult::of("alert"));
                    et.outcome = "alert".to_owned();
                }
                "timeout" => {
                    let elapsed = self.elapsed(start);
                    let message = format!(
                        "correlation timeout reached after {} for {} while processing event {index}, remaining steps skipped and event falls through to alert",
                        timedelta_str(elapsed),
                        self.label()
                    );
                    self.log_warning(message);
                    trace.stream_events.push(StreamEvent {
                        event_type: "timeout".to_owned(),
                        at_event_index: Some(index),
                        detail: Some(format!(
                            "timeout after {} mid-event; remaining steps skipped",
                            timedelta_str(elapsed)
                        )),
                    });
                    alerts.push(index);
                    result
                        .event_actions
                        .insert(index, ActionResult::of("alert"));
                    et.outcome = "timeout".to_owned();
                }
                _ => {}
            }
            trace.event_traces.push(et);
            index += 1;
        }
        result.events = alerts.iter().map(|&i| events[i].clone()).collect();
        result.origins = alerts;
        result.trace = trace;
        Ok(self.finish(result))
    }

    fn finish(&mut self, mut result: Correlated) -> Correlated {
        bound_trace(&mut result.trace, self.rt.limits.trace_text_bytes);
        result.captured = self.recorder.export();
        result.logs = std::mem::take(&mut self.logs);
        result
    }

    /// `_process_event_steps`: an interrupting action, or None when the event runs out of steps.
    pub(crate) fn steps(
        &mut self,
        steps: &[Step],
        events: &mut Vec<Map>,
        index: usize,
        start: DateTime<Utc>,
        first: usize,
        trace_steps: &mut Vec<StepTrace>,
    ) -> Result<Option<ActionResult>, Flow> {
        for (step_index, step) in steps.iter().enumerate().skip(first) {
            if self.elapsed(start) >= self.timeout {
                return Ok(Some(ActionResult::of("timeout")));
            }
            self.check_stop()?;
            if let Some(debug) = step.debug.as_deref().filter(|d| !d.is_empty()) {
                let scope = Scope {
                    event: &events[index],
                    events,
                };
                match render(self.rt.renderer, debug, scope) {
                    Ok(m) => self.log(Level::Debug, format!("correlation debug: {m}")),
                    Err(_) => self.log(
                        Level::Debug,
                        format!("failed to render debug template: {debug}"),
                    ),
                }
            }
            let t0 = Instant::now();
            let description = step.description.clone();
            let action = match &step.step {
                StepKind::Condition(c) => {
                    self.condition(c, events, index, start, description, t0, trace_steps)?
                }
                StepKind::Transform(t) => {
                    self.transform(t, events, index, step_index, description, t0, trace_steps)?
                }
                StepKind::Action(a) => {
                    self.action(a, events, index, description, t0, trace_steps)?
                }
            };
            if let Some(action) = action
                && action.is_interrupt()
            {
                return Ok(Some(action));
            }
        }
        Ok(None)
    }

    #[allow(clippy::too_many_arguments)]
    fn condition(
        &mut self,
        condition: &Condition,
        events: &mut Vec<Map>,
        index: usize,
        start: DateTime<Utc>,
        description: Option<String>,
        t0: Instant,
        trace_steps: &mut Vec<StepTrace>,
    ) -> Result<Option<ActionResult>, Flow> {
        let scope = Scope {
            event: &events[index],
            events,
        };
        let (result, mut expression) = self.evaluator.evaluate_traced(&condition.when, scope)?;
        expression.rendered_value = sanitize_opt(expression.rendered_value, self.rt.secrets);
        let mut ct = ConditionTrace {
            trace_type: "condition",
            expression,
            branch_taken: Branch::None,
            branch_steps: Vec::new(),
            error: None,
        };
        let finish = |ct: ConditionTrace, trace_steps: &mut Vec<StepTrace>| {
            trace_steps.push(StepTrace {
                description: description.clone(),
                step: StepKindTrace::Condition(ct),
                duration_ms: ms(t0),
            });
        };
        if let Some(error) = ct.expression.error.clone() {
            self.log(
                Level::Error,
                format!("error evaluating condition expression: {error}"),
            );
            ct.error = Some(error);
            finish(ct, trace_steps);
            return Err(Flow::Step);
        }
        let branch = if result {
            Some((Branch::Execute, &condition.execute))
        } else {
            condition
                .otherwise
                .as_ref()
                .filter(|o| !o.is_empty())
                .map(|o| (Branch::Else, o))
        };
        let Some((taken, steps)) = branch else {
            finish(ct, trace_steps);
            return Ok(None);
        };
        ct.branch_taken = taken;
        let mut branch_steps = Vec::new();
        let flow = self.steps(steps, events, index, start, 0, &mut branch_steps);
        ct.branch_steps = branch_steps;
        match flow {
            Ok(action) => {
                finish(ct, trace_steps);
                Ok(action)
            }
            Err(Flow::Step) => {
                finish(ct, trace_steps);
                Err(Flow::Step)
            }
            // a reset or an error out of a branch leaves the condition out of the trace, as
            // ace3's exception passes it by
            Err(other) => Err(other),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn transform(
        &mut self,
        transform: &Transform,
        events: &mut Vec<Map>,
        index: usize,
        step_index: usize,
        description: Option<String>,
        t0: Instant,
        trace_steps: &mut Vec<StepTrace>,
    ) -> Result<Option<ActionResult>, Flow> {
        let mut tt = TransformTrace {
            trace_type: "transform",
            transform_type: transform.kind.clone(),
            method: transform.method.clone(),
            command_type: transform.command.kind.clone(),
            rendered_command: None,
            property_name: None,
            property_value: None,
            result_count: None,
            merge_dropped: None,
            query_start_time: None,
            query_end_time: None,
            query_time_spec: None,
            error: None,
        };
        let call = Call {
            scope: Scope {
                event: &events[index],
                events,
            },
            transform_type: &transform.kind,
        };
        tt.rendered_command = sanitize_opt(
            self.command_summary(&transform.command, call),
            self.rt.secrets,
        );
        if let Some(query) = self.effective_query(&transform.command)?
            && let Ok((s, e)) = self.resolve_time_range(&query, &events[index], &transform.kind)
        {
            tt.query_start_time = Some(s);
            tt.query_end_time = Some(e);
            if let Some(source) = query
                .source
                .as_deref()
                .and_then(|n| self.rt.sources.get(n).ok())
                && let Ok(spec) = source.format_timespec_for_display(s, e)
            {
                tt.query_time_spec = spec;
            }
        }
        let push = |tt: TransformTrace, trace_steps: &mut Vec<StepTrace>| {
            trace_steps.push(StepTrace {
                description: description.clone(),
                step: StepKindTrace::Transform(tt),
                duration_ms: ms(t0),
            });
        };
        let call = Call {
            scope: Scope {
                event: &events[index],
                events,
            },
            transform_type: &transform.kind,
        };
        let outcome = self
            .execute_command(&transform.command, call)
            .and_then(|output| self.bounded(output));
        let output = match outcome {
            Ok(output) => output,
            Err(e) => {
                if matches!(self.check_stop(), Err(EngineError::Stopped)) {
                    return Err(Flow::Run(EngineError::Stopped));
                }
                let message = sanitize(&e, self.rt.secrets);
                self.log(
                    Level::Error,
                    format!("error executing transform command: {message}"),
                );
                tt.error = Some(message);
                push(tt, trace_steps);
                return Err(Flow::Step);
            }
        };
        let trimmed = output.trim_matches(crate::render::methods::is_space);
        tt.result_count = Some(
            splitlines(trimmed)
                .iter()
                .filter(|l| !l.trim_matches(crate::render::methods::is_space).is_empty())
                .count(),
        );
        let mut event = events[index].clone();
        let applied = apply(transform, &output, &mut event, events);
        let fail = |this: &mut Self, tt: &mut TransformTrace, e: String| {
            let message = sanitize(&e, this.rt.secrets);
            this.log(
                Level::Error,
                format!("error executing transform command: {message}"),
            );
            tt.error = Some(message);
        };
        match applied {
            Ok(Applied::Stream {
                events: stream,
                merge_dropped,
            }) => {
                tt.merge_dropped = merge_dropped;
                if stream.len() > self.rt.limits.stream_events {
                    let limit = self.rt.limits.stream_events;
                    fail(
                        self,
                        &mut tt,
                        format!(
                            "ace-rs limit: a stream transform made {} events, past its {limit}",
                            stream.len()
                        ),
                    );
                    push(tt, trace_steps);
                    return Err(Flow::Step);
                }
                if transform.method == "mutate"
                    && let Some(source) = self.command_source(&transform.command)
                {
                    self.current_source = Some(source);
                }
                push(tt, trace_steps);
                Err(Flow::Reset(stream, step_index + 1))
            }
            Ok(Applied::Event) => {
                events[index] = event;
                if transform.method == "property"
                    && let Some(name) = transform.property_name.as_deref().filter(|n| !n.is_empty())
                {
                    tt.property_name = Some(name.to_owned());
                    tt.property_value = Some(truncate_repr(events[index].get(name)));
                }
                push(tt, trace_steps);
                Ok(None)
            }
            Err(TransformError::Step(e)) => {
                fail(self, &mut tt, e);
                push(tt, trace_steps);
                Err(Flow::Step)
            }
            Err(TransformError::Run(e)) => Err(Flow::Run(e)),
        }
    }

    /// A command's output within its bound and the run's.
    fn bounded(&mut self, output: String) -> Result<String, String> {
        let limits = self.rt.limits;
        if output.len() > limits.command_output_bytes {
            return Err(format!(
                "ace-rs limit: the command output {} bytes, past its {}",
                output.len(),
                limits.command_output_bytes
            ));
        }
        self.output_bytes += output.len();
        if self.output_bytes > limits.run_output_bytes {
            return Err(format!(
                "ace-rs limit: the run's commands have output {} bytes, past its {}",
                self.output_bytes, limits.run_output_bytes
            ));
        }
        Ok(output)
    }

    fn action(
        &mut self,
        action: &Action,
        events: &[Map],
        index: usize,
        description: Option<String>,
        t0: Instant,
        trace_steps: &mut Vec<StepTrace>,
    ) -> Result<Option<ActionResult>, Flow> {
        let scope = Scope {
            event: &events[index],
            events,
        };
        let mut logs = Vec::new();
        let executed = execute_action(action, self.rt.renderer, scope, &mut logs);
        self.logs.extend(logs);
        let result = match executed {
            Ok(result) => result,
            Err(e) => {
                self.log(Level::Error, format!("error executing action: {e}"));
                trace_steps.push(StepTrace {
                    description,
                    step: StepKindTrace::Action(ActionTrace {
                        trace_type: "action",
                        action_type: action.kind.clone(),
                        rendered_log_message: None,
                        is_interrupt: false,
                        error: Some(e),
                    }),
                    duration_ms: ms(t0),
                });
                return Err(Flow::Step);
            }
        };
        // `_trace_action` renders the message again for the trace
        let rendered = action
            .log_message
            .as_deref()
            .filter(|m| !m.is_empty())
            .and_then(|m| render(self.rt.renderer, m, scope).ok())
            .map(|m| sanitize(&m, self.rt.secrets));
        trace_steps.push(StepTrace {
            description,
            step: StepKindTrace::Action(ActionTrace {
                trace_type: "action",
                action_type: result.action_type.clone(),
                rendered_log_message: rendered,
                is_interrupt: result.is_interrupt(),
                error: None,
            }),
            duration_ms: ms(t0),
        });
        Ok(Some(result))
    }
}

/// Each text the trace keeps cut to `max` bytes, at a character, with a marker.
fn bound_trace(trace: &mut CorrelationTrace, max: usize) {
    fn cut(text: &mut Option<String>, max: usize) {
        if let Some(t) = text
            && t.len() > max
        {
            let mut end = max;
            while !t.is_char_boundary(end) {
                end -= 1;
            }
            t.truncate(end);
            t.push_str("... (ace-rs: cut to its bound)");
        }
    }
    fn expression(e: &mut super::trace::ExpressionTrace, max: usize) {
        cut(&mut e.rendered_value, max);
        cut(&mut e.property_value, max);
        cut(&mut e.compare_value, max);
        cut(&mut e.error, max);
        for sub in e.sub_expressions.iter_mut().flatten() {
            expression(sub, max);
        }
    }
    fn walk(steps: &mut [StepTrace], max: usize) {
        for step in steps {
            match &mut step.step {
                StepKindTrace::Condition(c) => {
                    expression(&mut c.expression, max);
                    cut(&mut c.error, max);
                    walk(&mut c.branch_steps, max);
                }
                StepKindTrace::Transform(t) => {
                    cut(&mut t.rendered_command, max);
                    cut(&mut t.error, max);
                }
                StepKindTrace::Action(a) => {
                    cut(&mut a.rendered_log_message, max);
                    cut(&mut a.error, max);
                }
            }
        }
    }
    for et in &mut trace.event_traces {
        walk(&mut et.steps, max);
    }
}
