//! The part of Python's `argparse` the scripts use: options only, each `--long` with an optional
//! `-s`, taking one value, a value for each use (`action="append"`), any number of values
//! (`nargs="*"`), or none (`store_true`); `--name=value`, `-svalue`, and a long option shortened to
//! any prefix that names one option (`allow_abbrev`). A bad command line exits 2 with the usage
//! error on stderr, as argparse does; the text of the usage line is shorter than argparse's.

use std::collections::BTreeMap;

use super::super::script::ScriptExit;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// One value; the last use wins.
    One,
    /// `action="append"`.
    Append,
    /// `nargs="*"`; the last use wins.
    Many,
    /// `action="store_true"`.
    Flag,
}

pub struct Opt {
    pub long: &'static str,
    pub short: Option<&'static str>,
    pub kind: Kind,
    pub required: bool,
}

impl Opt {
    pub const fn new(long: &'static str, kind: Kind) -> Opt {
        Opt {
            long,
            short: None,
            kind,
            required: false,
        }
    }

    pub const fn short(mut self, short: &'static str) -> Opt {
        self.short = Some(short);
        self
    }

    pub const fn required(mut self) -> Opt {
        self.required = true;
        self
    }

    fn display(&self) -> String {
        match self.short {
            Some(s) => format!("{s}/{}", self.long),
            None => self.long.to_owned(),
        }
    }
}

/// What the command line set, by each option's long name.
#[derive(Debug, Default)]
pub struct Parsed {
    values: BTreeMap<&'static str, Vec<String>>,
    flags: BTreeMap<&'static str, bool>,
}

impl Parsed {
    pub fn one(&self, long: &str) -> Option<&str> {
        self.values
            .get(long)
            .and_then(|v| v.last())
            .map(String::as_str)
    }

    /// An append or `*` option's values, None when it wasn't given.
    pub fn many(&self, long: &str) -> Option<&[String]> {
        self.values.get(long).map(Vec::as_slice)
    }

    pub fn flag(&self, long: &str) -> bool {
        self.flags.get(long).copied().unwrap_or(false)
    }
}

/// The usage error argparse exits with.
pub fn usage_error(prog: &str, message: &str) -> ScriptExit {
    ScriptExit {
        code: 2,
        stderr: format!("usage: {prog} [-h] ...\n{prog}: error: {message}\n"),
    }
}

/// argparse's test for a negative number, which is a value rather than an option:
/// `^-\d+$|^-\d*\.\d+$`.
fn negative_number(arg: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    let Some(rest) = arg.strip_prefix('-') else {
        return false;
    };
    match rest.split_once('.') {
        None => digits(rest),
        Some((int, frac)) => (int.is_empty() || digits(int)) && digits(frac),
    }
}

enum Arg<'a> {
    /// An option, the value given with `=` or joined to a short one.
    Option(&'a Opt, Option<String>),
    /// Something that looks like an option and isn't one.
    Unknown,
    /// A value.
    Value,
}

fn classify<'a>(prog: &str, opts: &'a [Opt], arg: &str) -> Result<Arg<'a>, ScriptExit> {
    if !arg.starts_with('-') || arg == "-" {
        return Ok(Arg::Value);
    }
    if let Some(o) = opts.iter().find(|o| o.long == arg || o.short == Some(arg)) {
        return Ok(Arg::Option(o, None));
    }
    if let Some((name, value)) = arg.split_once('=')
        && let Some(o) = opts
            .iter()
            .find(|o| o.long == name || o.short == Some(name))
    {
        return Ok(Arg::Option(o, Some(value.to_owned())));
    }
    // a long option's prefix, or a short option with its value joined
    let matches: Vec<(&Opt, Option<String>)> = if arg.starts_with("--") {
        let (name, value) = match arg.split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (arg, None),
        };
        opts.iter()
            .filter(|o| o.long.starts_with(name))
            .map(|o| (o, value.clone()))
            .collect()
    } else {
        let short: String = arg.chars().take(2).collect();
        let rest = &arg[short.len()..];
        let mut found: Vec<(&Opt, Option<String>)> = opts
            .iter()
            .filter(|o| o.short == Some(short.as_str()))
            .map(|o| (o, Some(rest.to_owned())))
            .collect();
        found.extend(
            opts.iter()
                .filter(|o| o.long.starts_with(arg))
                .map(|o| (o, None)),
        );
        found
    };
    match matches.len() {
        0 => {}
        1 => {
            let (o, v) = matches.into_iter().next().expect("one");
            return Ok(Arg::Option(o, v));
        }
        _ => {
            let names: Vec<String> = matches.iter().map(|(o, _)| o.long.to_owned()).collect();
            let name = arg.split_once('=').map_or(arg, |(n, _)| n);
            return Err(usage_error(
                prog,
                &format!("ambiguous option: {name} could match {}", names.join(", ")),
            ));
        }
    }
    if negative_number(arg) || arg.contains(' ') {
        return Ok(Arg::Value);
    }
    Ok(Arg::Unknown)
}

/// Parses `argv` as `prog`'s parser, with no positional arguments.
pub fn parse(prog: &str, opts: &[Opt], argv: &[String]) -> Result<Parsed, ScriptExit> {
    let mut parsed = Parsed::default();
    let mut extras: Vec<String> = Vec::new();
    let mut i = 0;
    let mut rest_positional = false;
    while i < argv.len() {
        let arg = &argv[i];
        i += 1;
        if rest_positional {
            extras.push(arg.clone());
            continue;
        }
        if arg == "--" {
            rest_positional = true;
            continue;
        }
        let (opt, joined) = match classify(prog, opts, arg)? {
            Arg::Value | Arg::Unknown => {
                extras.push(arg.clone());
                continue;
            }
            Arg::Option(o, v) => (o, v),
        };
        // the values that follow, up to the next option
        let mut following = |max: usize| -> Result<Vec<String>, ScriptExit> {
            let mut taken = Vec::new();
            while taken.len() < max && i < argv.len() && argv[i] != "--" {
                match classify(prog, opts, &argv[i])? {
                    Arg::Value => {
                        taken.push(argv[i].clone());
                        i += 1;
                    }
                    _ => break,
                }
            }
            Ok(taken)
        };
        match opt.kind {
            Kind::Flag => {
                if joined.is_some() {
                    return Err(usage_error(
                        prog,
                        &format!(
                            "argument {}: ignored explicit argument {}",
                            opt.display(),
                            py_quote(joined.as_deref().unwrap_or(""))
                        ),
                    ));
                }
                parsed.flags.insert(opt.long, true);
            }
            Kind::One | Kind::Append => {
                let value = match joined {
                    Some(v) => v,
                    None => match following(1)?.pop() {
                        Some(v) => v,
                        None => {
                            return Err(usage_error(
                                prog,
                                &format!("argument {}: expected one argument", opt.display()),
                            ));
                        }
                    },
                };
                let entry = parsed.values.entry(opt.long).or_default();
                if opt.kind == Kind::One {
                    entry.clear();
                }
                entry.push(value);
            }
            Kind::Many => {
                let values = match joined {
                    Some(v) => vec![v],
                    None => following(usize::MAX)?,
                };
                parsed.values.insert(opt.long, values);
            }
        }
    }
    let missing: Vec<String> = opts
        .iter()
        .filter(|o| o.required && !parsed.values.contains_key(o.long))
        .map(Opt::display)
        .collect();
    if !missing.is_empty() {
        return Err(usage_error(
            prog,
            &format!(
                "the following arguments are required: {}",
                missing.join(", ")
            ),
        ));
    }
    if !extras.is_empty() {
        return Err(usage_error(
            prog,
            &format!("unrecognized arguments: {}", extras.join(" ")),
        ));
    }
    Ok(parsed)
}

fn py_quote(s: &str) -> String {
    crate::value::py_repr(s)
}

/// `float(text)`, or argparse's error for the option.
pub fn float(prog: &str, option: &str, text: &str) -> Result<f64, ScriptExit> {
    py_float(text).ok_or_else(|| {
        usage_error(
            prog,
            &format!("argument {option}: invalid float value: {}", py_quote(text)),
        )
    })
}

/// `int(text)`, or argparse's error for the option.
pub fn int(prog: &str, option: &str, text: &str) -> Result<i64, ScriptExit> {
    py_int(text).ok_or_else(|| {
        usage_error(
            prog,
            &format!("argument {option}: invalid int value: {}", py_quote(text)),
        )
    })
}

/// Python's `float()` of a string: surrounding whitespace, `_` between digits, `inf` and `nan`.
pub fn py_float(text: &str) -> Option<f64> {
    let t = super::strip(text);
    let lower = t.to_ascii_lowercase();
    let unsigned = lower.trim_start_matches(['+', '-']);
    if lower.len() - unsigned.len() > 1 {
        return None;
    }
    let negative = lower.starts_with('-');
    let special = match unsigned {
        "inf" | "infinity" => Some(f64::INFINITY),
        "nan" => Some(f64::NAN),
        _ => None,
    };
    if let Some(v) = special {
        return Some(if negative { -v } else { v });
    }
    let cleaned = without_underscores(&lower)?;
    if !cleaned
        .chars()
        .all(|c| c.is_ascii_digit() || "+-.e".contains(c))
        || !cleaned.chars().any(|c| c.is_ascii_digit())
    {
        return None;
    }
    cleaned.parse().ok()
}

/// Python's `int()` of a string.
pub fn py_int(text: &str) -> Option<i64> {
    let t = super::strip(text);
    let cleaned = without_underscores(t)?;
    let digits = cleaned.trim_start_matches(['+', '-']);
    if cleaned.len() - digits.len() > 1
        || digits.is_empty()
        || !digits.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    cleaned.parse().ok()
}

/// The text with each `_` that sits between two digits removed; None for any other `_`.
fn without_underscores(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    for (i, &c) in chars.iter().enumerate() {
        if c == '_' {
            let before = i > 0 && chars[i - 1].is_ascii_digit();
            let after = chars.get(i + 1).is_some_and(char::is_ascii_digit);
            if !(before && after) {
                return None;
            }
            continue;
        }
        out.push(c);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPTS: [Opt; 4] = [
        Opt::new("--domain", Kind::One).short("-d").required(),
        Opt::new("--type", Kind::Append).short("-t"),
        Opt::new("--no-fallback", Kind::Flag),
        Opt::new("--browser", Kind::Many),
    ];

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn options_read_as_argparse_reads_them() {
        let p = parse(
            "x.py",
            &OPTS,
            &argv(&[
                "-dexample.com",
                "--ty",
                "MX",
                "-t=A",
                "--no-f",
                "--browser",
                "a",
                "b",
            ]),
        )
        .expect("parses");
        assert_eq!(p.one("--domain"), Some("example.com"));
        assert_eq!(
            p.many("--type"),
            Some(&["MX".to_owned(), "A".to_owned()][..])
        );
        assert!(p.flag("--no-fallback"));
        assert_eq!(p.many("--browser").map(<[String]>::len), Some(2));
        // a value may look like a negative number
        let p = parse("x.py", &OPTS, &argv(&["--domain", "-5"])).expect("parses");
        assert_eq!(p.one("--domain"), Some("-5"));
    }

    #[test]
    fn a_bad_command_line_exits_2() {
        for args in [
            &[][..],
            &["--domain"][..],
            &["--domain", "a", "extra"][..],
            &["--domain", "a", "--nope"][..],
        ] {
            let e = parse("x.py", &OPTS, &argv(args)).expect_err("refused");
            assert_eq!(e.code, 2, "{args:?}");
        }
        assert_eq!(py_float(" 1_0.5 "), Some(10.5));
        assert_eq!(py_float("abc"), None);
        assert_eq!(py_int("+08"), Some(8));
        assert_eq!(py_int("1.0"), None);
    }
}
