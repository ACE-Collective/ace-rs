//! Running tshark and capinfos in the sandbox runner, and reading what they print, as ace3's
//! pcap.py does (`_run_tool`, `parse_capinfos`, `_parse_statistics`, `_parse_fields`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use ace_pycompat::pystr;
use ace_results::types::pcap::{Capture, Endpoint, Flow, Statistics};
use ace_sdk::tools::{STDERR_TAIL_BYTES, ToolOutput, ToolRun, ToolStatus, ToolStop};
use ace_sdk::{ModuleError, TaskContext};
use regex::Regex;

/// ace3's `PcapError`: tshark couldn't dissect the capture, which the analysis records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapError(pub String);

/// The fields of each packet of the field run, by name, each its values.
pub type Layers = BTreeMap<String, Vec<String>>;

/// The packets the field run prints: those that carry one of these. Hosts and flows come from the
/// statistics run, which sees every packet.
pub const DISPLAY_FILTER: &str =
    "dns || tls.handshake || http.request || http.response || http2.headers || dhcp || nbns";

/// The fields the field run prints.
pub const TSHARK_FIELDS: [&str; 39] = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.stream",
    "udp.stream",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "dns.flags.response",
    "dns.qry.name",
    "dns.resp.name",
    "dns.resp.type",
    "dns.cname",
    "dns.a",
    "dns.aaaa",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
    "tls.handshake.ja4",
    "tls.handshake.random",
    "tls.handshake.certificate",
    "http.request.method",
    "http.host",
    "http.request.full_uri",
    "http.user_agent",
    "http.response.code",
    "http.content_type",
    "http.request_in",
    "http2.headers.method",
    "http2.headers.scheme",
    "http2.headers.authority",
    "http2.headers.path",
    "http2.headers.user_agent",
    "dhcp.option.hostname",
    "dhcp.hw.mac_addr",
    "nbns.name",
];

/// The protocols whose objects tshark exports, each into `objects/<protocol>`.
pub const EXPORT_OBJECT_PROTOCOLS: [&str; 5] = ["http", "smb", "ftp-data", "tftp", "imf"];

/// The statistics run's arguments after `-n -r <capture>`.
pub const STATISTICS_ARGS: [&str; 13] = [
    "-q",
    "-z",
    "io,stat,0",
    "-z",
    "endpoints,eth",
    "-z",
    "endpoints,ip",
    "-z",
    "endpoints,ipv6",
    "-z",
    "conv,tcp",
    "-z",
    "conv,udp",
];

/// The field run's arguments after `-n -r <capture>`: JSON of the first `max_field_packets`, the
/// objects exported, and the key log, if any.
pub fn field_args(max_field_packets: u64, keylog: Option<&Path>) -> Vec<String> {
    let mut args = vec![
        "-T".to_owned(),
        "json".to_owned(),
        "-Y".to_owned(),
        format!("frame.number <= {max_field_packets} && ({DISPLAY_FILTER})"),
    ];
    for field in TSHARK_FIELDS {
        args.extend(["-e".to_owned(), field.to_owned()]);
    }
    for protocol in EXPORT_OBJECT_PROTOCOLS {
        args.extend([
            "--export-objects".to_owned(),
            format!("{protocol},objects/{protocol}"),
        ]);
    }
    if let Some(keylog) = keylog {
        args.extend([
            "-o".to_owned(),
            format!("tls.keylog_file:{}", keylog.display()),
        ]);
    }
    args
}

/// What a run gave: its stdout, as ace3 decodes it, and the files it kept.
pub struct Ran {
    pub stdout: String,
    pub output: ToolOutput,
}

/// ace3's `_run_tool`: runs `tool` with `args` in the runner and returns its stdout, or the
/// capture's failure: a run stopped at its timeout or for its output, or one that exited non-zero
/// with nothing on stdout. A tool that couldn't be run at all is the node's (the task fails).
pub fn run<S>(
    ctx: &TaskContext<S>,
    tool: &str,
    args: Vec<String>,
    reads: &[PathBuf],
    timeout: Duration,
    keep_tree: bool,
) -> Result<Result<Ran, PcapError>, ModuleError> {
    let mut run = ToolRun::new(tool, args).timeout(timeout);
    for path in reads {
        run = run.read(path);
    }
    if keep_tree {
        // and when tshark dies of the file size limit, as ace3 collects what it exported before then
        run = run.keep_tree().keep_stopped();
    }
    let output = ctx.run_tool(run)?;
    let returncode = match output.status {
        ToolStatus::Stopped(ToolStop::Timeout) => {
            return Ok(Err(PcapError(format!(
                "{tool} failed: command timed out after {}",
                timedelta(timeout)
            ))));
        }
        ToolStatus::Stopped(ToolStop::Output) => {
            return Ok(Err(PcapError(format!(
                "{tool} failed: command wrote more than {} bytes of output",
                ace_sdk::tools::MAX_OUTPUT_BYTES
            ))));
        }
        // SIGXFSZ: ace3's tool dies of it, and its launcher exits 128 plus the signal
        ToolStatus::Stopped(ToolStop::FileSize) => 128 + 25,
        // ace3's sandbox lets these through; here the runner killed the tool
        ToolStatus::Stopped(stop @ (ToolStop::Process | ToolStop::Program)) => {
            return Ok(Err(PcapError(format!(
                "{tool} failed: {}",
                stop.describe()
            ))));
        }
        ToolStatus::Exited(code) => code,
        ToolStatus::Signaled(signal) => 128 + signal,
    };
    let stdout = pystr::decode_utf8_replace(&output.stdout).into_owned();
    if returncode != 0 && pystr::strip(&stdout).is_empty() {
        return Ok(Err(PcapError(format!(
            "{tool} exited with {returncode}: {}",
            stderr_tail(&output)?
        ))));
    }
    if returncode != 0 {
        // a capture cut short mid-packet exits non-zero after printing everything before the cut
        tracing::info!(
            "{tool} exited with {returncode} but produced output: {}",
            stderr_tail(&output)?
        );
    }
    Ok(Ok(Ran { stdout, output }))
}

/// The last 500 characters of the end of stderr ace3 keeps, stripped.
fn stderr_tail(output: &ToolOutput) -> std::io::Result<String> {
    let bytes = &output.stderr;
    let tail = &bytes[bytes.len().saturating_sub(STDERR_TAIL_BYTES)..];
    let text = pystr::decode_utf8_replace(tail);
    let text = pystr::strip(&text);
    let chars: Vec<char> = text.chars().collect();
    Ok(chars[chars.len().saturating_sub(500)..].iter().collect())
}

/// `str(datetime.timedelta(seconds=...))` for whole seconds under a day, such as `0:02:00`.
pub fn timedelta(duration: Duration) -> String {
    let seconds = duration.as_secs();
    format!(
        "{}:{:02}:{:02}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

static CAPINFOS_FIELD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([A-Za-z][A-Za-z ]+):\s+(.*?)\s*$").expect("the pattern compiles")
});
static CAPINFOS_ENCAPSULATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s+Encapsulation = (.+?) \(").expect("the pattern compiles"));

/// `parse_capinfos`: the capture's summary from `capinfos -M -S`, times in epoch seconds. Its
/// `file_name` is the analysis's to set.
pub fn parse_capinfos(output: &str) -> Capture {
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut encapsulations: Vec<String> = Vec::new();
    for line in pystr::splitlines(output) {
        if let Some(m) = CAPINFOS_ENCAPSULATION.captures(line) {
            if !encapsulations.iter().any(|e| e == &m[1]) {
                encapsulations.push(m[1].to_owned());
            }
            continue;
        }
        if let Some(m) = CAPINFOS_FIELD.captures(line) {
            fields
                .entry(pystr::strip(&m[1]).to_owned())
                .or_insert_with(|| m[2].to_owned());
        }
    }
    let first_word = |key: &str| {
        fields
            .get(key)
            // str.split() with no separator: runs of whitespace
            .and_then(|value| {
                value
                    .split(pystr::is_space)
                    .find(|w| !w.is_empty())
                    .map(str::to_owned)
            })
    };
    let int = |key: &str| first_word(key).and_then(|w| py_int(&w));
    let float = |key: &str| first_word(key).and_then(|w| py_float(&w));
    Capture {
        format: fields.get("File type").cloned(),
        size: int("File size"),
        packets: int("Number of packets"),
        first: float("Earliest packet time"),
        last: float("Latest packet time"),
        duration: float("Capture duration"),
        application: fields.get("Capture application").cloned(),
        interfaces: int("Number of interfaces in file"),
        encapsulations,
        // True when packets are in time order, so capture order is chronological
        strict_time_order: match fields.get("Strict time order").map(String::as_str) {
            Some("True") => Some(true),
            Some("False") => Some(false),
            _ => None,
        },
        file_name: String::new(),
    }
}

/// Python's `int()` of a word, None where it raises: digits, with a sign and underscores between
/// them.
fn py_int(word: &str) -> Option<u64> {
    let digits = word.strip_prefix('+').unwrap_or(word);
    if digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    digits.replace('_', "").parse().ok()
}

/// Python's `float()` of a word, None where it raises.
fn py_float(word: &str) -> Option<f64> {
    if word.contains('_') {
        return None;
    }
    match word.to_ascii_lowercase().trim_start_matches(['+', '-']) {
        "inf" | "infinity" | "nan" => word.to_ascii_lowercase().parse().ok(),
        _ => word.parse().ok(),
    }
}

static ENDPOINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\S+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s*$").expect("the pattern compiles")
});
static CONVERSATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(\S+)\s+<->\s+(\S+)\s+\d+\s+\S+ \S+\s+\d+\s+\S+ \S+\s+(\d+)\s+(\S+ \S+)\s+([\d.]+)\s+([\d.]+)\s*$",
    )
    .expect("the pattern compiles")
});
static IO_STAT_TOTAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\|\s*[\d.]+\s*<>\s*[\d.]+\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|")
        .expect("the pattern compiles")
});

/// A number `\d+` matched, which Python's `int()` takes whatever its digits' script.
fn digits(text: &str) -> Result<u64, ModuleError> {
    let ascii: String = text
        .chars()
        .map(|c| c.to_digit(10).map_or(c, |d| char::from(b'0' + d as u8)))
        .collect();
    ascii
        .parse()
        .map_err(|_| ModuleError::other(format!("invalid literal for int(): {text:?}")))
}

/// `[\d.]+` matched, which Python's `float()` may refuse, as ace3's module then raises.
fn decimal(text: &str) -> Result<f64, ModuleError> {
    py_float(text).ok_or_else(|| {
        ModuleError::other(format!(
            "ValueError: could not convert string to float: {}",
            ace_pycompat::repr::repr(text)
        ))
    })
}

/// `_parse_statistics`: packets, endpoints and conversations from the statistics run, each table
/// most packets first and cut to `max_rows`, with its whole count.
pub fn parse_statistics(output: &str, max_rows: usize) -> Result<Statistics, ModuleError> {
    #[derive(PartialEq)]
    enum Section {
        None,
        Mac,
        Ip,
        Tcp,
        Udp,
        Io,
    }
    let (mut packets, mut bytes) = (0, 0);
    let (mut mac, mut ip, mut flows) = (Vec::new(), Vec::new(), Vec::new());
    let mut section = Section::None;
    for line in pystr::splitlines(output) {
        let stripped = pystr::strip(line);
        if stripped.starts_with("Ethernet Endpoints") {
            section = Section::Mac;
        } else if stripped.starts_with("IPv4 Endpoints") || stripped.starts_with("IPv6 Endpoints") {
            section = Section::Ip;
        } else if stripped.starts_with("TCP Conversations") {
            section = Section::Tcp;
        } else if stripped.starts_with("UDP Conversations") {
            section = Section::Udp;
        } else if stripped.starts_with("| IO Statistics") {
            section = Section::Io;
        } else if section == Section::Io {
            if let Some(m) = IO_STAT_TOTAL.captures(stripped) {
                packets = digits(&m[1])?;
                bytes = digits(&m[2])?;
            }
        } else if section == Section::Mac || section == Section::Ip {
            if let Some(m) = ENDPOINT.captures(stripped) {
                let row = Endpoint {
                    address: m[1].to_owned(),
                    packets: digits(&m[2])?,
                    bytes: digits(&m[3])?,
                };
                if section == Section::Mac {
                    mac.push(row);
                } else {
                    ip.push(row);
                }
            }
        } else if (section == Section::Tcp || section == Section::Udp)
            && let Some(m) = CONVERSATION.captures(stripped)
        {
            flows.push(Flow {
                protocol: if section == Section::Tcp {
                    "tcp"
                } else {
                    "udp"
                }
                .to_owned(),
                a: m[1].to_owned(),
                b: m[2].to_owned(),
                frames: digits(&m[3])?,
                bytes: m[4].to_owned(),
                start: decimal(&m[5])?,
                duration: decimal(&m[6])?,
            });
        }
    }
    // most first, ties in the order tshark printed them, as Python's sorted(reverse=True)
    mac.sort_by_key(|e: &Endpoint| std::cmp::Reverse(e.packets));
    ip.sort_by_key(|e: &Endpoint| std::cmp::Reverse(e.packets));
    flows.sort_by_key(|f: &Flow| std::cmp::Reverse(f.frames));
    let (mac_total, ip_total, flows_total) = (mac.len(), ip.len(), flows.len());
    mac.truncate(max_rows);
    ip.truncate(max_rows);
    flows.truncate(max_rows);
    Ok(Statistics {
        packets: Some(packets),
        bytes: Some(bytes),
        mac: Some(mac),
        ip: Some(ip),
        flows: Some(flows),
        mac_total: Some(mac_total as u64),
        ip_total: Some(ip_total as u64),
        flows_total: Some(flows_total as u64),
    })
}

/// `_parse_fields`: each packet's layers from the field run's JSON, as `json.loads` reads it; its
/// error is the capture's.
pub fn parse_fields(output: &str) -> Result<Vec<Layers>, PcapError> {
    if pystr::strip(output).is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = match serde_json::from_str(output) {
        Ok(value) => value,
        // Python's own error, and what it reads where serde_json refuses it (a lone surrogate)
        Err(_) => match ace_pycompat::json::loads(output) {
            Ok(value) => pycompat_value(&value),
            Err(e) => {
                return Err(PcapError(format!(
                    "unable to parse tshark output: {}",
                    e.message
                )));
            }
        },
    };
    let packets = match value {
        serde_json::Value::Array(packets) => packets,
        // iterating a dict gives its keys, and a str its characters: none is a dict
        _ => Vec::new(),
    };
    Ok(packets
        .iter()
        .filter_map(serde_json::Value::as_object)
        .map(|packet| {
            let layers = packet
                .get("_source")
                .and_then(|s| s.get("layers"))
                .and_then(serde_json::Value::as_object);
            layers
                .into_iter()
                .flatten()
                .map(|(field, values)| (field.clone(), strings(values)))
                .collect()
        })
        .collect())
}

/// A field's values, as tshark prints them: a list of strings.
fn strings(values: &serde_json::Value) -> Vec<String> {
    match values {
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| match item {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect(),
        serde_json::Value::String(s) => vec![s.clone()],
        other => vec![other.to_string()],
    }
}

/// A `json.loads` value as serde_json's.
fn pycompat_value(value: &ace_pycompat::json::Value) -> serde_json::Value {
    use ace_pycompat::json::Value as V;
    match value {
        V::Null => serde_json::Value::Null,
        V::Bool(b) => serde_json::Value::Bool(*b),
        V::Int(text) => text.parse::<serde_json::Number>().map_or_else(
            |_| serde_json::Value::String(text.clone()),
            serde_json::Value::Number,
        ),
        V::Float(f) => serde_json::Number::from_f64(*f)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        V::Str(s) => serde_json::Value::String(s.as_str().to_owned()),
        V::Array(items) => serde_json::Value::Array(items.iter().map(pycompat_value).collect()),
        V::Object(pairs) => serde_json::Value::Object(
            pairs
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), pycompat_value(v)))
                .collect(),
        ),
    }
}

/// `_first`: a field's first value.
pub fn first<'a>(layers: &'a Layers, field: &str) -> Option<&'a str> {
    layers
        .get(field)
        .and_then(|v| v.first())
        .map(String::as_str)
}

/// A field's values, none when it's absent.
pub fn all<'a>(layers: &'a Layers, field: &str) -> &'a [String] {
    layers.get(field).map_or(&[], Vec::as_slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capinfos_is_read_as_ace3_reads_it() {
        let output = "File name:           input\nFile type:           pcapng\n\
            Number of packets:   41\nFile size:           11652 bytes\n\
            Capture duration:    0.044872099 seconds\nEarliest packet time: 1792604746.451966886\n\
            Strict time order:   True\nCapture application: Dumpcap (Wireshark) 4.4.19\n\
            Number of interfaces in file: 1\nInterface #0 info:\n\
            \x20                    Encapsulation = Ethernet (1 - ether)\n";
        let capture = parse_capinfos(output);
        assert_eq!(capture.format.as_deref(), Some("pcapng"));
        assert_eq!(capture.packets, Some(41));
        assert_eq!(capture.size, Some(11652));
        assert_eq!(capture.first, Some(1792604746.451967));
        assert_eq!(capture.last, None);
        assert_eq!(capture.encapsulations, ["Ethernet"]);
        assert_eq!(capture.strict_time_order, Some(true));
        assert_eq!(capture.interfaces, Some(1));
    }

    #[test]
    fn a_timeout_reads_as_pythons_timedelta() {
        assert_eq!(timedelta(Duration::from_secs(120)), "0:02:00");
        assert_eq!(timedelta(Duration::from_secs(30)), "0:00:30");
        assert_eq!(timedelta(Duration::from_secs(3725)), "1:02:05");
    }

    #[test]
    fn malformed_json_is_the_captures_error_in_pythons_words() {
        let error = parse_fields("[{\"_source\": ").unwrap_err();
        assert!(
            error
                .0
                .starts_with("unable to parse tshark output: Expecting value"),
            "{}",
            error.0
        );
        assert_eq!(parse_fields("  ").unwrap(), Vec::<Layers>::new());
        let layers =
            parse_fields(r#"[{"_source": {"layers": {"dns.a": ["1.2.3.4"]}}}, 3]"#).unwrap();
        assert_eq!(layers.len(), 1);
        assert_eq!(first(&layers[0], "dns.a"), Some("1.2.3.4"));
    }
}
