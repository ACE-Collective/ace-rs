//! Jinja2's `cycler` and `joiner` globals (`jinja2/utils.py`). `range`, `dict` and `namespace` are
//! in [`super::ops`] and minijinja.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use minijinja::value::{Object, ObjectRepr, Rest, Value};
use minijinja::{Error, ErrorKind, State};

/// `cycler(*items)`: `next()` gives each item in turn, `current` the one `next()` gives next, and
/// `reset()` starts again.
#[derive(Debug)]
pub struct Cycler {
    items: Vec<Value>,
    pos: AtomicUsize,
}

impl Object for Cycler {
    fn repr(self: &Arc<Self>) -> ObjectRepr {
        ObjectRepr::Plain
    }
    fn get_value(self: &Arc<Self>, key: &Value) -> Option<Value> {
        match key.as_str()? {
            "current" => self.items.get(self.pos.load(Ordering::Relaxed)).cloned(),
            "items" => Some(super::py::PyList::of(self.items.clone())),
            _ => None,
        }
    }
    fn call_method(
        self: &Arc<Self>,
        _: &mut State<'_, '_>,
        method: &str,
        args: &[Value],
    ) -> Result<Value, Error> {
        if !args.is_empty() {
            return Err(super::py::type_error(format!(
                "{method}() takes 1 positional argument but {} were given",
                args.len() + 1
            )));
        }
        match method {
            "next" | "__next__" => {
                let pos = self.pos.load(Ordering::Relaxed);
                self.pos
                    .store((pos + 1) % self.items.len(), Ordering::Relaxed);
                Ok(self.items[pos].clone())
            }
            "reset" => {
                self.pos.store(0, Ordering::Relaxed);
                Ok(Value::from(()))
            }
            _ => Err(Error::new(
                ErrorKind::UnknownMethod,
                format!("'Cycler' object has no attribute '{method}'"),
            )),
        }
    }
}

pub fn cycler(_: &State, items: Rest<Value>) -> Result<Value, Error> {
    if items.is_empty() {
        return Err(super::py::type_error(
            "at least one item has to be provided",
        ));
    }
    Ok(Value::from_object(Cycler {
        items: items.0,
        pos: AtomicUsize::new(0),
    }))
}

/// `joiner(sep=", ")`: called, it gives `""` the first time and `sep` after.
#[derive(Debug)]
pub struct Joiner {
    sep: Value,
    used: AtomicBool,
}

impl Object for Joiner {
    fn repr(self: &Arc<Self>) -> ObjectRepr {
        ObjectRepr::Plain
    }
    fn call(self: &Arc<Self>, _: &mut State<'_, '_>, args: &[Value]) -> Result<Value, Error> {
        if !args.is_empty() {
            return Err(super::py::type_error(format!(
                "__call__() takes 1 positional argument but {} were given",
                args.len() + 1
            )));
        }
        if self.used.swap(true, Ordering::Relaxed) {
            Ok(self.sep.clone())
        } else {
            Ok(Value::from(""))
        }
    }
}

pub fn joiner(_: &State, sep: Option<Value>) -> Result<Value, Error> {
    Ok(Value::from_object(Joiner {
        sep: sep.unwrap_or_else(|| Value::from(", ")),
        used: AtomicBool::new(false),
    }))
}
