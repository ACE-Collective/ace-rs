//! What ace3's observable classes (`saq/observables/`) do to a value as it is set: some refuse it,
//! so `add_observable_by_spec` returns None and the module goes on without it, and some change it.
//! The core applies these rules to every observable a result or a submission adds (ace-core's
//! `observable_rules`), so a module's result needn't, though a module may use them to know what
//! will land.
//!
//! ace3 picks a class by the type's exact name (`observable_types.classes`); a type that extends
//! another in `observable_types.yaml` (`email_from` extends `email_address`, a site's type may
//! extend `fqdn`) has no class unless it is named there, so its values are kept as given. These
//! rules go by the exact name too. Whatever the class, ace3's registry
//! (`ObservableRegistry.record`) refuses a value that is empty or only whitespace.

use std::borrow::Cow;

use ace_pycompat::pystr;
use ace_results::{NewObservable, ObservableKind};

use crate::email_threads::{normalize_email_address, normalize_message_id};

/// The value ace3 keeps of `value` as an observable of `kind`: as given or changed, or Err with
/// why it refuses it.
pub fn value(kind: ObservableKind, value: &str) -> Result<Cow<'_, str>, &'static str> {
    let kept = class_value(kind, value)?;
    if pystr::strip(&kept).is_empty() {
        return Err("the value is empty");
    }
    Ok(kept)
}

/// `add_observable_by_spec(kind, value)`: the observable ace3 would add, or None where it refuses
/// the value.
pub fn new(kind: ObservableKind, value: &str) -> Option<NewObservable> {
    self::value(kind, value)
        .ok()
        .map(|kept| NewObservable::new(kind, kept.into_owned()))
}

/// What the value setter of the class ace3 maps `kind` to keeps, before the registry's check for
/// an empty value: `create_observable`, which the hunter calls before it adds the observable to a
/// root.
pub fn class_value(kind: ObservableKind, value: &str) -> Result<Cow<'_, str>, &'static str> {
    let stripped = || Cow::Borrowed(pystr::strip(value));
    match kind.as_str() {
        // FQDNObservable: validators.domain on the value as given, then stripped
        "fqdn" => ace_pycompat::validators::domain(value)
            .then(stripped)
            .ok_or("not a valid fqdn"),
        // IPObservable and its subclass EmailFirstHopIPObservable
        "ip" | "email_first_hop_ip" => {
            let v = pystr::strip(value);
            ace_pycompat::ipaddress::ip_address(v)
                .map(|_| Cow::Borrowed(v))
                .map_err(|_| "not a valid ip address")
        }
        // IPv4Observable parses the value as given, and keeps it stripped
        "ipv4" => ace_pycompat::ipaddress::ipv4_address(value)
            .map(|_| stripped())
            .map_err(|_| "not a valid ipv4 address"),
        "ip_conversation" => {
            // src_dst, each an ip address
            let v = pystr::strip(value);
            let parts: Vec<&str> = v.splitn(3, '_').collect();
            let ip = |p: &str| ace_pycompat::ipaddress::ip_address(p).is_ok();
            (parts.len() == 2 && parts.iter().all(|p| !p.is_empty() && ip(p)))
                .then_some(Cow::Borrowed(v))
                .ok_or("not a valid ip conversation")
        }
        "ip_full_conversation" => {
            // src!src_port!dst!dst_port: ip addresses and what Python's int() reads
            let v = pystr::strip(value);
            let parts: Vec<&str> = v.splitn(5, '!').collect();
            let ip = |p: &str| ace_pycompat::ipaddress::ip_address(p).is_ok();
            let ok = parts.len() == 4
                && parts.iter().all(|p| !p.is_empty())
                && ip(parts[0])
                && ip(parts[2])
                && is_python_int(parts[1])
                && is_python_int(parts[3]);
            ok.then_some(Cow::Borrowed(v))
                .ok_or("not a valid ip full conversation")
        }
        // the ipv4 conversations check only how many parts there are
        "ipv4_conversation" => {
            let v = pystr::strip(value);
            (v.splitn(3, '_').count() == 2)
                .then_some(Cow::Borrowed(v))
                .ok_or("not a valid ipv4 conversation")
        }
        "ipv4_full_conversation" => {
            let v = pystr::strip(value);
            (v.splitn(5, ':').count() == 4)
                .then_some(Cow::Borrowed(v))
                .ok_or("not a valid ipv4 full conversation")
        }
        "url" => names_a_host(value)
            .then_some(Cow::Borrowed(value))
            .ok_or("the url has no host"),
        "user_agent"
        | "uri_path"
        | "hostname"
        | "asset"
        | "indicator"
        | "mutex"
        | "windows_registry"
        | "windows_service"
        | "snort_sig"
        | "av_streetname"
        | "ids_streetname"
        | "yara_rule"
        | "email_subject"
        | "email_x_mailer"
        | "email_conversation"
        | "aws_access_key_id"
        | "aws_principal_id"
        | "aws_username"
        | "aws_instance_id"
        | "aws_security_group_id"
        | "aws_private_dns_name" => Ok(stripped()),
        "aws_account_id" => {
            // twelve characters str.isdigit takes
            let v = pystr::strip(value);
            (v.chars().count() == 12 && pystr::str_is_digit(v))
                .then_some(Cow::Borrowed(v))
                .ok_or("not a valid AWS account id")
        }
        // UserObservable: stripped, and only what follows its last backslash
        "user" => Ok(Cow::Borrowed(
            pystr::strip(value).rsplit('\\').next().unwrap_or_default(),
        )),
        "mac_address" => crate::layer2::normalize_mac_address(value)
            .map(Cow::Owned)
            .ok_or("does not parse as a mac address"),
        // EmailAddressObservable: normalized, or as given where it doesn't normalize
        "email_address" => {
            if !value.contains('@') {
                return Err("missing @ in email address");
            }
            Ok(normalize_email_address(value).map_or(Cow::Borrowed(value), Cow::Owned))
        }
        "message_id" => {
            if !value.contains('@') {
                return Err("not a valid message-id");
            }
            Ok(Cow::Owned(normalize_message_id(value)))
        }
        "email_delivery" => email_delivery(value).map(Cow::Owned),
        "md5" => hash(value, "d41d8cd98f00b204e9800998ecf8427e"),
        "sha1" => hash(value, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        "sha256" => hash(
            value,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        // YaraStringObservable: rule:$string, split at the last colon
        "yara_string" => {
            let v = pystr::strip(value);
            v.contains(':')
                .then_some(Cow::Borrowed(v))
                .ok_or("expected format for yara string is rule:$string")
        }
        // FileLocationObservable: hostname@full_path, split at the first @
        "file_location" => match value.split_once('@') {
            None => Err("invalid file_location (missing @)"),
            Some((host, path))
                if pystr::strip(host).is_empty() || pystr::strip(path).is_empty() =>
            {
                Err("file_location missing hostname or path")
            }
            Some(_) => Ok(Cow::Borrowed(value)),
        },
        // FileObservable asserts its value is a sha256 (`^[a-f0-9]{64}$`, any case), which fails
        // the module in ace3
        "file" => {
            let hex = value.strip_suffix('\n').unwrap_or(value);
            (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
                .then_some(Cow::Borrowed(value))
                .ok_or("a file's value is not a sha256")
        }
        // the string_* types, email_body, email_header, file_path, file_name and every type with
        // no class
        _ => Ok(Cow::Borrowed(value)),
    }
}

/// EmailDeliveryObservable: `message_id|mailbox`, split at the last `|`, each normalized.
fn email_delivery(value: &str) -> Result<String, &'static str> {
    let invalid = "invalid format for email_delivery";
    let (message_id, mailbox) = pystr::strip(value).rsplit_once('|').ok_or(invalid)?;
    if message_id.is_empty() || mailbox.is_empty() {
        return Err(invalid);
    }
    // ace3 raises an AttributeError, which fails the module, where the mailbox doesn't normalize
    let mailbox = normalize_email_address(mailbox).ok_or("the mailbox is not an email address")?;
    Ok(format!(
        "{}|{}",
        pystr::strip(&normalize_message_id(message_id)),
        pystr::strip(&mailbox)
    ))
}

/// `validate_hash_value`: stripped, and refused when all zeros or the hash of empty content.
fn hash<'a>(value: &'a str, empty_content: &str) -> Result<Cow<'a, str>, &'static str> {
    let v = pystr::strip(value);
    if v.chars().all(|c| c == '0') {
        return Err("the hash is all zeros");
    }
    if pystr::lower(v) == empty_content {
        return Err("the hash of empty content");
    }
    Ok(Cow::Borrowed(v))
}

/// Whether Python's `int(text)` reads `text`: whitespace around a sign and decimal digits, with
/// single underscores between them.
fn is_python_int(text: &str) -> bool {
    let t = pystr::strip(text);
    let t = t.strip_prefix(['+', '-']).unwrap_or(t);
    !t.is_empty()
        && !t.starts_with('_')
        && !t.ends_with('_')
        && !t.contains("__")
        && t.chars().all(|c| c == '_' || pystr::is_decimal(c))
}

/// ace3's `URLObservable` refuses an http, https or ftp URL with no host: a browser drops tabs and
/// line breaks, reads `\` as `/` and skips the slashes after the scheme, and a host needs a
/// letter or a digit. A URL `urlsplit` can't read is kept.
pub fn names_a_host(url: &str) -> bool {
    let Ok(split) = ace_pycompat::parse::urlsplit(url, "", true) else {
        return true;
    };
    if !matches!(split.scheme.as_str(), "http" | "https" | "ftp") {
        return true;
    }
    let rest: String = url
        .split_once(':')
        .map_or("", |(_, rest)| rest)
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect::<String>()
        .replace('\\', "/");
    let rest = rest.trim_start_matches('/');
    match ace_pycompat::parse::urlsplit(&format!("{}://{rest}", split.scheme), "", true) {
        Ok(split) => split
            .hostname()
            .unwrap_or_default()
            .chars()
            .any(pystr::is_alnum),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (type, value, what ace3 keeps): each run through `create_observable` and the registry's
    /// empty check in ace3's container, None where it refuses the value.
    const CASES: &[(&str, &str, Option<&str>)] = &[
        ("fqdn", "GTS Root R1", None),
        ("fqdn", "WE1", None),
        ("fqdn", "DigiCert Global G2 TLS RSA SHA256 2020 CA1", None),
        ("fqdn", "example.com", Some("example.com")),
        ("fqdn", " example.com", None),
        ("fqdn", "Example.COM", Some("Example.COM")),
        ("fqdn", "m\u{fc}nchen.de", Some("m\u{fc}nchen.de")),
        ("fqdn", "@x.com", None),
        ("fqdn", "example.com\n", None),
        ("fqdn", "xn--mnchen-3ya.de", Some("xn--mnchen-3ya.de")),
        ("ip", "10.0.0.1 ", Some("10.0.0.1")),
        ("ip", "10.0.0", None),
        ("ip", " ::1 ", Some("::1")),
        ("ip", "fe80::1%eth0", Some("fe80::1%eth0")),
        ("ip", "1.2.3.4/32", None),
        ("ip", "1.2.3.4\u{a0}", Some("1.2.3.4")),
        ("email_first_hop_ip", " 1.2.3.4", Some("1.2.3.4")),
        ("email_first_hop_ip", "x", None),
        ("ipv4", "1.2.3.4", Some("1.2.3.4")),
        ("ipv4", " 1.2.3.4", None),
        ("ipv4", "1.2.3.4 ", None),
        ("ipv4", "::1", None),
        ("ipv4", "01.2.3.4", None),
        (
            "ip_conversation",
            "1.2.3.4_5.6.7.8",
            Some("1.2.3.4_5.6.7.8"),
        ),
        ("ip_conversation", " 1.2.3.4_::1 ", Some("1.2.3.4_::1")),
        ("ip_conversation", "1.2.3.4_x", None),
        ("ip_conversation", "1.2.3.4_5.6.7.8_9", None),
        ("ip_conversation", "_1.2.3.4", None),
        (
            "ip_full_conversation",
            "1.2.3.4!80!5.6.7.8!443",
            Some("1.2.3.4!80!5.6.7.8!443"),
        ),
        (
            "ip_full_conversation",
            "1.2.3.4! 80 !5.6.7.8!+443",
            Some("1.2.3.4! 80 !5.6.7.8!+443"),
        ),
        (
            "ip_full_conversation",
            "1.2.3.4!8_0!5.6.7.8!4_43",
            Some("1.2.3.4!8_0!5.6.7.8!4_43"),
        ),
        ("ip_full_conversation", "1.2.3.4!x!5.6.7.8!443", None),
        ("ip_full_conversation", "1.2.3.4!80!5.6.7.8!443!1", None),
        ("ip_full_conversation", "1.2.3.4!80!5.6.7.8", None),
        (
            "ip_full_conversation",
            "1.2.3.4!-1!5.6.7.8!\u{663}",
            Some("1.2.3.4!-1!5.6.7.8!\u{663}"),
        ),
        ("ip_full_conversation", "1.2.3.4!!5.6.7.8!443", None),
        (
            "ip_full_conversation",
            "1.2.3.4!0!5.6.7.8!443",
            Some("1.2.3.4!0!5.6.7.8!443"),
        ),
        ("ipv4_conversation", "a_b", Some("a_b")),
        ("ipv4_conversation", "_", Some("_")),
        ("ipv4_conversation", "a", None),
        ("ipv4_conversation", "a_b_c", None),
        ("ipv4_full_conversation", "a:b:c:d", Some("a:b:c:d")),
        ("ipv4_full_conversation", ":::", Some(":::")),
        ("ipv4_full_conversation", "a:b:c", None),
        ("ipv4_full_conversation", "a:b:c:d:e", None),
        ("url", "https:..", None),
        (
            "url",
            "https://example.com/a",
            Some("https://example.com/a"),
        ),
        ("url", " https://example.com", Some(" https://example.com")),
        ("url", "http://%", None),
        (
            "url",
            "https:\\\\evil.example.com",
            Some("https:\\\\evil.example.com"),
        ),
        ("url", "https:/\t/evil.com", Some("https:/\t/evil.com")),
        ("url", "mailto:x", Some("mailto:x")),
        ("url", "http://[x/", Some("http://[x/")),
        ("url", "ftp://-", None),
        ("user_agent", " Mozilla ", Some("Mozilla")),
        ("uri_path", " /a ", Some("/a")),
        ("hostname", " HOST ", Some("HOST")),
        ("asset", " a ", Some("a")),
        ("indicator", " i ", Some("i")),
        ("mutex", " m ", Some("m")),
        ("windows_registry", " r ", Some("r")),
        ("windows_service", " s ", Some("s")),
        ("snort_sig", " 1:2:3 ", Some("1:2:3")),
        ("snort_sig", "x", Some("x")),
        ("av_streetname", " a ", Some("a")),
        ("ids_streetname", " i ", Some("i")),
        ("yara_rule", " r ", Some("r")),
        ("email_subject", " s ", Some("s")),
        ("email_x_mailer", " m ", Some("m")),
        ("aws_access_key_id", " k ", Some("k")),
        ("aws_principal_id", " p ", Some("p")),
        ("aws_username", " u ", Some("u")),
        ("aws_instance_id", " i ", Some("i")),
        ("aws_security_group_id", " g ", Some("g")),
        ("aws_private_dns_name", " d ", Some("d")),
        ("aws_account_id", " 123456789012 ", Some("123456789012")),
        ("aws_account_id", "12345678901", None),
        (
            "aws_account_id",
            "\u{661}\u{662}\u{663}\u{664}\u{665}\u{666}\u{667}\u{668}\u{669}\u{660}\u{661}\u{662}",
            Some(
                "\u{661}\u{662}\u{663}\u{664}\u{665}\u{666}\u{667}\u{668}\u{669}\u{660}\u{661}\u{662}",
            ),
        ),
        ("aws_ami_id", " a ", Some(" a ")),
        ("user", " DOM\\bob ", Some("bob")),
        ("user", "host\\DOM\\bob", Some("bob")),
        ("user", "DOM\\", None),
        ("user", "  ", None),
        ("user", "Bob", Some("Bob")),
        (
            "mac_address",
            "AA:BB:CC:DD:EE:FF",
            Some("aa-bb-cc-dd-ee-ff"),
        ),
        ("mac_address", "aabb.ccdd.eeff", Some("aa-bb-cc-dd-ee-ff")),
        ("mac_address", "xx", None),
        (
            "mac_address",
            " aa-bb-cc-dd-ee-ff ",
            Some("aa-bb-cc-dd-ee-ff"),
        ),
        (
            "email_address",
            "John <John.Davison@Company.com>",
            Some("john.davison@company.com"),
        ),
        ("email_address", "nope", None),
        ("email_address", " a@b.com ", Some("a@b.com")),
        ("email_address", "<<a@b.com>>", Some("a@b.com")),
        ("email_address", "a@b@c", Some("a@b@c")),
        ("email_address", "@", Some("@")),
        ("email_address", "\"x\" <@>", Some("\"x\" <@>")),
        ("email_address", "a@b.com\u{1c}", Some("a@b.com")),
        ("email_from", "Foo <A@B.com>", Some("Foo <A@B.com>")),
        ("email_to", "nope", Some("nope")),
        ("email_cc", "nope", Some("nope")),
        ("message_id", "abc@x", Some("<abc@x>")),
        ("message_id", " <abc@x> ", Some("<abc@x>")),
        ("message_id", "nope", None),
        ("email_delivery", "<abc@x>|A@B.com", Some("<abc@x>|a@b.com")),
        (
            "email_delivery",
            " abc@x | a@b.com ",
            Some("<abc@x>|a@b.com"),
        ),
        ("email_delivery", "nope", None),
        ("email_delivery", "|a@b.com", None),
        ("email_delivery", "abc@x|", None),
        ("email_delivery", "a|b|c@d.com", Some("<a|b>|c@d.com")),
        ("email_delivery", "mid|nope", Some("<mid>|nope")),
        ("email_delivery", "mid|a@b.com\n", Some("<mid>|a@b.com")),
        ("email_conversation", " a@b|c@d ", Some("a@b|c@d")),
        ("email_conversation", "a", Some("a")),
        ("md5", " D41D8CD98F00B204E9800998ECF8427E ", None),
        ("md5", "0000", None),
        ("md5", " abc ", Some("abc")),
        ("md5", "\u{a0}abc\u{a0}", Some("abc")),
        ("md5", "   ", None),
        ("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", None),
        (
            "sha256",
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            None,
        ),
        ("sha256", "", None),
        ("yara_string", " rule:$s ", Some("rule:$s")),
        ("yara_string", "rule", None),
        ("yara_string", ":", Some(":")),
        ("file_location", "h@/p", Some("h@/p")),
        ("file_location", "h@ ", None),
        ("file_location", "nohost", None),
        ("file_location", " @/p", None),
        ("file_location", "h@p@q", Some("h@p@q")),
        ("string_js", " x ", Some(" x ")),
        ("email_body", " b ", Some(" b ")),
        ("email_header", " h ", Some(" h ")),
        ("file_path", " C:\\x", Some(" C:\\x")),
        ("file_name", " a.exe ", Some(" a.exe ")),
        ("command_line", " cmd ", Some(" cmd ")),
        ("signature_id", " s ", Some(" s ")),
        ("test", " t ", Some(" t ")),
        ("hunt", "", None),
        ("hunt", "   ", None),
        ("ja3", " j ", Some(" j ")),
        // a subtype has no class of its own in ace3: fqdn's rule doesn't apply
        (
            "email_dkim_signing_domain",
            "GTS Root R1",
            Some("GTS Root R1"),
        ),
    ];

    #[test]
    fn values_are_refused_or_changed_as_ace3_does() {
        let mut wrong = Vec::new();
        for &(kind, given, expected) in CASES {
            let kind: ObservableKind = kind.parse().expect("a built-in kind");
            let kept = value(kind, given).ok();
            if kept.as_deref() != expected {
                wrong.push(format!("{kind} {given:?}: {kept:?}, ace3 {expected:?}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn email_delivery_refuses_a_mailbox_that_does_not_normalize() {
        // ace3 raises AttributeError here, which fails the module rather than refusing the value
        assert!(value(ObservableKind::EmailDelivery, "mid|<>").is_err());
    }

    #[test]
    fn a_file_is_a_sha256() {
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856";
        assert!(value(ObservableKind::File, sha256).is_ok());
        assert!(value(ObservableKind::File, &sha256.to_uppercase()).is_ok());
        assert!(value(ObservableKind::File, "abc").is_err());
    }

    #[test]
    fn a_refusal_says_why() {
        assert_eq!(
            value(ObservableKind::Fqdn, "GTS Root R1"),
            Err("not a valid fqdn")
        );
        assert_eq!(value(ObservableKind::Hunt, " "), Err("the value is empty"));
        assert!(new(ObservableKind::Fqdn, "GTS Root R1").is_none());
        assert_eq!(
            new(ObservableKind::Fqdn, "example.com").map(|o| o.value),
            Some("example.com".to_owned())
        );
    }

    #[test]
    fn urls_name_a_host_as_ace3_reads_them() {
        assert!(names_a_host("https://example.com/a"));
        assert!(names_a_host("HTTP://Upper.example.com/a b"));
        assert!(names_a_host("http://[x/"));
        assert!(names_a_host("https:\\\\evil.example.com"));
        assert!(!names_a_host("http://%"));
        assert!(!names_a_host("https://.."));
    }
}
