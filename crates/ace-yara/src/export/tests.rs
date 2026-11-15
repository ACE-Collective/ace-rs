//! ace3's `tests/saq/observables/test_export.py`, case by case: each test names the case it ports.
//! The cases about ace3's state file, its export targets and `--force` have no counterpart: the
//! rules are part of the ruleset's build, and `ace-core`'s `rulesets` tests cover when it runs.

use super::*;

fn config() -> ExportConfig {
    ExportConfig::default()
}

fn entry(id: i64, observable_type: &str, value: &str) -> ExportEntry {
    ExportEntry {
        id,
        export_type: observable_type.to_owned(),
        observable_type: observable_type.to_owned(),
        value: value.to_owned(),
    }
}

fn detection(id: i64, observable_type: &str, value: &str) -> Detection {
    Detection {
        id,
        observable_type: observable_type.to_owned(),
        value: value.to_owned(),
    }
}

/// ace3's `etc/observable_types.yaml` edges the subtype cases stand on.
fn ancestors(observable_type: &str) -> Vec<String> {
    match observable_type {
        "email_reply_to" | "email_from" => vec!["email_address".to_owned()],
        "email_dkim_signing_domain" => vec!["fqdn".to_owned()],
        _ => Vec::new(),
    }
}

fn compile(source: &str) -> yara_x::Rules {
    let mut compiler = new_compiler();
    compiler.new_namespace(NAMESPACE);
    if let Err(error) = compiler.add_source(source.as_bytes()) {
        panic!("{source}\ndoesn't compile: {error}");
    }
    let rules = compiler.build();
    // ace3 compiles its lines with error_on_warning
    assert!(
        rules.warnings().is_empty(),
        "{source}\nwarns: {:?}",
        rules
            .warnings()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );
    rules
}

/// Compiles generated string lines into a rule that hits when one does: ace3's
/// `compile_string_line`.
fn compile_lines(lines: &str) -> yara_x::Rules {
    compile(&format!(
        "rule t {{ strings:\n{lines} condition: any of them }}"
    ))
}

/// The ASCII and wide strings the export writes for an "ascii wide nocase" bounded value: ace3's
/// `compile_bounded`.
fn compile_bounded(value: &str, family: Family) -> yara_x::Rules {
    compile_lines(&format!(
        "$a = {} ascii nocase\n$b = {} nocase\n",
        format_bounded_yara_regex(value, family, false),
        format_bounded_yara_regex(value, family, true),
    ))
}

/// The identifiers of the strings that matched, in the rules' order.
fn matched(rules: &yara_x::Rules, data: &[u8]) -> Vec<String> {
    let mut scanner = yara_x::Scanner::new(rules);
    let results = scanner.scan(data).expect("scans");
    let mut identifiers = Vec::new();
    for rule in results.matching_rules() {
        for pattern in rule.patterns() {
            if pattern.matches().next().is_some() {
                identifiers.push(pattern.identifier().to_owned());
            }
        }
    }
    identifiers
}

fn hits(rules: &yara_x::Rules, data: &[u8]) -> bool {
    !matched(rules, data).is_empty()
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// A generated export's file for a type.
fn rule_of<'a>(export: &'a Export, observable_type: &str) -> &'a str {
    let name = format!("{observable_type}.yar");
    export
        .files
        .iter()
        .find(|file| file.name == name)
        .map(|file| file.source.as_str())
        .unwrap_or_else(|| panic!("no {name} in {:?}", export.report))
}

fn has_file(export: &Export, observable_type: &str) -> bool {
    let name = format!("{observable_type}.yar");
    export.files.iter().any(|file| file.name == name)
}

fn generated(config: &ExportConfig, detections: &[Detection]) -> Export {
    generate(
        config,
        &export_list(config, detections, ancestors),
        "11/15/2026",
    )
}

/// The export as the namespace it is in a ruleset, with its index.
fn ruleset_of(export: &Export) -> crate::Ruleset {
    let dir = tempfile::tempdir().unwrap();
    let namespace = dir.path().join(NAMESPACE);
    std::fs::create_dir(&namespace).unwrap();
    for file in &export.files {
        std::fs::write(namespace.join(&file.name), &file.source).unwrap();
    }
    let loaded = crate::load_dir(dir.path(), &crate::LoadOptions::default()).expect("loads");
    assert_eq!(loaded.left_out().count(), 0);
    loaded.ruleset
}

// export list and fingerprinting

/// `test_export_list_fingerprint_is_order_independent`, with ace3's own hash.
#[test]
fn the_list_s_fingerprint_is_ace3_s_and_order_independent() {
    let a = ExportList::new(vec![
        entry(1, "fqdn", "a.com"),
        entry(2, "url", "http://b.com"),
    ]);
    let b = ExportList::new(vec![
        entry(2, "url", "http://b.com"),
        entry(1, "fqdn", "a.com"),
    ]);
    assert_eq!(a.fingerprint(), b.fingerprint());
    // sha256 of '[["fqdn",1,"a.com"],["url",2,"http://b.com"]]'
    assert_eq!(
        a.fingerprint(),
        "99b0a068e8ff589411bae8ee8bf42ec88199d89975327b5ec69bbfe94d19a225"
    );
    // as json.dumps(ensure_ascii=True) writes a string: escapes of four hex digits, in surrogates
    // past the basic plane
    let mut text = String::new();
    python_json_string(&mut text, "caf\u{e9} \u{1f600} \"\\\n\u{1}");
    let u = "\\u";
    assert_eq!(
        text,
        format!("\"caf{u}00e9 {u}d83d{u}de00 \\\"\\\\\\n{u}0001\"")
    );
}

/// `test_export_list_fingerprint_changes`, its five lists.
#[test]
fn the_list_s_fingerprint_changes_with_the_list() {
    let original = ExportList::new(vec![entry(1, "fqdn", "a.com")]).fingerprint();
    for entries in [
        vec![entry(1, "fqdn", "a.com"), entry(2, "fqdn", "b.com")],
        vec![],
        vec![entry(1, "fqdn", "changed.com")],
        vec![entry(1, "url", "a.com")],
        // the id: each string is named after it
        vec![entry(2, "fqdn", "a.com")],
    ] {
        assert_ne!(original, ExportList::new(entries).fingerprint());
    }
}

/// `test_export_list_entries_by_type`.
#[test]
fn the_list_groups_its_entries_by_type() {
    let list = ExportList::new(vec![
        entry(2, "fqdn", "b.com"),
        entry(1, "fqdn", "a.com"),
        entry(3, "url", "http://c.com"),
    ]);
    assert_eq!(list.types(), ["fqdn", "url"]);
    let grouped = list.entries_by_type();
    assert_eq!(
        grouped["fqdn"].iter().map(|e| e.id).collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(grouped["url"].iter().map(|e| e.id).collect::<Vec<_>>(), [3]);
}

/// `test_build_export_list_filters_by_type_and_length`.
#[test]
fn the_export_list_filters_by_type_and_length() {
    let config = ExportConfig {
        export_list: vec!["fqdn".to_owned(), "ip".to_owned()],
        minimum_length: 5,
        ..config()
    };
    let list = export_list(
        &config,
        &[
            detection(1, "fqdn", "evil.example.com"),
            detection(5, "fqdn", "a.com"),
            detection(2, "ip", "192.168.1.1"),
            detection(3, "ip", "::1"),
            detection(4, "url", "http://not-configured.example.com"),
        ],
        ancestors,
    );
    // ::1 is under the minimum, a.com is exactly at it, url isn't configured
    let got: Vec<(&str, i64)> = list
        .entries()
        .iter()
        .map(|e| (e.export_type.as_str(), e.id))
        .collect();
    assert_eq!(got, [("fqdn", 1), ("fqdn", 5), ("ip", 2)]);
}

/// `test_select_detections_ignores_blank_configured_entries`.
#[test]
fn a_blank_configured_type_covers_nothing() {
    let config = ExportConfig {
        export_list: vec![String::new(), "   ".to_owned()],
        minimum_length: 0,
        ..config()
    };
    assert!(export_list(&config, &[detection(1, "", "x")], ancestors).is_empty());
}

/// `test_build_export_list_includes_subtypes`.
#[test]
fn a_configured_type_covers_the_types_that_extend_it() {
    let config = ExportConfig {
        export_list: vec!["email_address".to_owned()],
        ..config()
    };
    let list = export_list(
        &config,
        &[
            detection(1, "email_reply_to", "reply@example.com"),
            detection(2, "email_from", "from@example.com"),
            detection(3, "email_address", "plain@example.com"),
        ],
        ancestors,
    );
    let got: Vec<(&str, &str, i64)> = list
        .entries()
        .iter()
        .map(|e| (e.export_type.as_str(), e.observable_type.as_str(), e.id))
        .collect();
    assert_eq!(
        got,
        [
            ("email_address", "email_reply_to", 1),
            ("email_address", "email_from", 2),
            ("email_address", "email_address", 3)
        ]
    );
}

/// `test_build_export_list_most_specific_configured_type_wins`.
#[test]
fn the_most_specific_configured_type_wins() {
    let config = ExportConfig {
        export_list: vec!["email_address".to_owned(), "email_reply_to".to_owned()],
        ..config()
    };
    let list = export_list(
        &config,
        &[detection(1, "email_reply_to", "reply@example.com")],
        ancestors,
    );
    assert_eq!(list.entries()[0].export_type, "email_reply_to");
    assert_eq!(list.len(), 1);
}

/// `test_build_export_list_applies_minimum_length_to_subtypes`.
#[test]
fn the_minimum_length_applies_to_subtypes() {
    let config = ExportConfig {
        export_list: vec!["email_address".to_owned()],
        ..config()
    };
    let list = export_list(
        &config,
        &[
            detection(1, "email_reply_to", "a@b"),
            detection(2, "email_reply_to", "reply@example.com"),
        ],
        ancestors,
    );
    let got: Vec<(&str, i64)> = list
        .entries()
        .iter()
        .map(|e| (e.export_type.as_str(), e.id))
        .collect();
    assert_eq!(got, [("email_address", 2)]);
}

/// `test_string_modifiers`.
#[test]
fn a_type_without_modifiers_takes_the_default() {
    assert_eq!(
        config().string_modifiers("fqdn"),
        "ascii wide nocase fullword"
    );
    assert_eq!(config().string_modifiers("ip"), "ascii wide nocase");
}

/// `test_format_yara_string`.
#[test]
fn a_text_string_is_escaped() {
    assert_eq!(format_yara_string("a\"b\\c\r\nd"), "a\\\"b\\\\cd");
    // a value embedded in JSON carries twice the backslashes
    assert_eq!(format_yara_json_string("a\\c"), "a\\\\\\\\c");
}

// bounded strings

/// `test_format_yara_regex_escapes_specials`.
#[test]
fn a_regex_s_specials_are_escaped() {
    assert_eq!(format_yara_regex("a/b.c?d(e)"), "a\\/b\\.c\\?d\\(e\\)");
    assert_eq!(format_yara_regex("a\r\nb"), "ab");
    assert_eq!(
        format_yara_regex("\\^$|*+[]{}"),
        "\\\\\\^\\$\\|\\*\\+\\[\\]\\{\\}"
    );
}

/// What ace3's tests don't have: a value outside ASCII in the ASCII regex. It stays as it is, as
/// in ace3, and yara-x matches its UTF-8 bytes, with no case folding outside ASCII, as libyara.
#[test]
fn a_regex_matches_a_value_outside_ascii_by_its_bytes() {
    assert_eq!(format_yara_regex("\u{e9}\t"), "\u{e9}\t");
    let value = "http://evil.example.com/\u{e9}t\t\u{e9}";
    let rules = compile_bounded(value, Family::Hostname);
    assert_eq!(
        matched(&rules, format!("see {value} here").as_bytes()),
        ["$a"]
    );
    assert_eq!(
        matched(
            &rules,
            format!("see {} here", value.replace("evil", "EVIL")).as_bytes()
        ),
        ["$a"]
    );
    assert!(!hits(
        &rules,
        "see http://evil.example.com/et\te here".as_bytes()
    ));
    assert!(!hits(
        &rules,
        "see http://evil.example.com/\u{c9}t\t\u{c9} here".as_bytes()
    ));
    assert!(!hits(
        &rules,
        b"see http://evil.example.com/\xe9t\t\xe9 here"
    ));
}

/// `test_bounded_url_rejects_hyphen_prefix`, its 13 rows.
#[test]
fn a_bounded_hostname_doesn_t_match_inside_a_longer_one() {
    let rules = compile_bounded("evil-example.com", Family::Hostname);
    for (data, expected) in [
        // the alert that started this in ace3: the address in its plain text part
        (
            b"assistance with connecting. (alice_smith@acme-evil-example.com)\n5. It is".to_vec(),
            false,
        ),
        (utf16("alice_smith@acme-evil-example.com"), false),
        (b"my-evil-example.com xevil-example.com".to_vec(), false),
        (b"evil-example.community".to_vec(), false),
        (b"cdn.evil-example.com-edge.net".to_vec(), false),
        (b"evil-example.com.au".to_vec(), false),
        (b"evil-example.com".to_vec(), true),
        (b"https://evil-example.com/login.php".to_vec(), true),
        (b"admin@evil-example.com".to_vec(), true),
        (b"cdn.evil-example.com".to_vec(), true),
        (b"Block evil-example.com.".to_vec(), true),
        (utf16("evil-example.com"), true),
        (utf16("see evil-example.com."), true),
    ] {
        assert_eq!(
            hits(&rules, &data),
            expected,
            "{:?}",
            String::from_utf8_lossy(&data)
        );
    }
}

/// `test_bounded_email_address`, its 7 rows.
#[test]
fn a_bounded_email_address() {
    let rules = compile_bounded("bob@evil.com", Family::EmailAddress);
    for (data, expected) in [
        ("<bob@evil.com>", true),
        ("mailto:bob@evil.com", true),
        ("jimbob@evil.com", false),
        ("x.bob@evil.com", false),
        ("jim+bob@evil.com", false),
        ("bob@evil.com.au", false),
        ("bob@evil.company", false),
    ] {
        assert_eq!(hits(&rules, data.as_bytes()), expected, "{data}");
    }
}

/// `test_bounded_ipv4`, its 8 rows.
#[test]
fn a_bounded_ipv4() {
    let config = ExportConfig {
        boundaries: [("ip".to_owned(), "ip".to_owned())].into(),
        ..config()
    };
    let family = config.string_boundary("ip", "1.2.3.4").unwrap();
    assert_eq!(family, Family::Ipv4);
    let rules = compile_bounded("1.2.3.4", family);
    for (data, expected) in [
        ("src=1.2.3.4 dst", true),
        ("1.2.3.4:443", true),
        ("seen 1.2.3.4.", true),
        ("1.2.3.4", true),
        ("5.1.2.3.4", false),
        ("11.2.3.4", false),
        ("1.2.3.45", false),
        ("1.2.3.4.5", false),
    ] {
        assert_eq!(hits(&rules, data.as_bytes()), expected, "{data}");
    }
}

/// `test_bounded_ipv6`, its 3 rows.
#[test]
fn a_bounded_ipv6() {
    let family = config().string_boundary("ip", "2001:db8::1").unwrap();
    assert_eq!(family, Family::Ipv6);
    let rules = compile_bounded("2001:db8::1", family);
    for (data, expected) in [
        ("addr 2001:db8::1 port", true),
        ("2001:db8::12", false),
        ("a2001:db8::1", false),
    ] {
        assert_eq!(hits(&rules, data.as_bytes()), expected, "{data}");
    }
}

/// `test_bounded_hex`, its 3 rows.
#[test]
fn a_bounded_hex() {
    let rules = compile_bounded("d41d8cd98f00b204e9800998ecf8427e", Family::Hex);
    for (data, expected) in [
        ("md5=d41d8cd98f00b204e9800998ecf8427e;", true),
        ("ad41d8cd98f00b204e9800998ecf8427e", false),
        ("d41d8cd98f00b204e9800998ecf8427e00ff", false),
    ] {
        assert_eq!(hits(&rules, data.as_bytes()), expected, "{data}");
    }
}

/// `test_bounded_edges_only_where_word_chars`.
#[test]
fn an_edge_is_bounded_only_where_it_s_a_word_character() {
    let value = "http://evil.example.com/a?x=";
    // "h" is a word character, "=" isn't: a left boundary only
    let regex = format_bounded_yara_regex(value, Family::Hostname, false);
    assert!(regex.starts_with("/(^|"), "{regex}");
    assert!(regex.ends_with("x=/"), "{regex}");
    let rules = compile_bounded(value, Family::Hostname);
    assert!(hits(&rules, b"http://evil.example.com/a?x=123"));
    assert!(!hits(&rules, b"xhttp://evil.example.com/a?x="));
}

/// `test_bounded_edges_absent_is_a_plain_regex`.
#[test]
fn a_value_with_no_word_edge_is_a_plain_regex() {
    assert_eq!(
        format_bounded_yara_regex("/a.b/", Family::Hostname, false),
        "/\\/a\\.b\\//"
    );
}

/// `test_bounded_wide_non_ascii_neighbours`, its 12 rows.
#[test]
fn a_wide_boundary_is_any_code_unit_that_isn_t_a_word_character() {
    for (value, family, data, expected) in [
        // the wide modifier would make each boundary one ASCII byte and a NUL, so none of these would hit
        ("evil.com", Family::Hostname, "\u{feff}evil.com", true),
        ("evil.com", Family::Hostname, "\u{4e2d}evil.com ", true),
        ("evil.com", Family::Hostname, "see evil.com\u{306f}", true),
        (
            "evil.com",
            Family::Hostname,
            "\u{feff}block evil.com.\u{306f}",
            true,
        ),
        ("1.2.3.4", Family::Ipv4, "\u{feff}1.2.3.4\r\n", true),
        (
            "d41d8cd98f00b204e9800998ecf8427e",
            Family::Hex,
            "\u{feff}d41d8cd98f00b204e9800998ecf8427e",
            true,
        ),
        (
            "2001:db8::1",
            Family::Ipv6,
            "\u{4e2d}2001:db8::1\u{4e2d}",
            true,
        ),
        (
            "bob@evil.com",
            Family::EmailAddress,
            "\u{4e2d}bob@evil.com",
            true,
        ),
        // and a word character in UTF-16 is still no boundary
        ("evil.com", Family::Hostname, "\u{feff}acme-evil.com", false),
        ("evil.com", Family::Hostname, "evil.com.au\u{4e2d}", false),
        ("1.2.3.4", Family::Ipv4, "\u{feff}5.1.2.3.4", false),
        (
            "bob@evil.com",
            Family::EmailAddress,
            "jim.bob@evil.com",
            false,
        ),
    ] {
        assert_eq!(
            hits(&compile_bounded(value, family), &utf16(data)),
            expected,
            "{value} in {data:?}"
        );
    }
}

/// `test_bounded_wide_non_ascii_value_matches_like_the_wide_modifier`.
#[test]
fn a_wide_regex_matches_what_the_wide_modifier_does() {
    // the wide modifier puts a NUL after each UTF-8 byte; the wide regex has to hit the same data
    let value = "http://evil.example.com/\u{e9}t\u{e9}";
    let wide_data: Vec<u8> = format!(" {value} ").bytes().flat_map(|b| [b, 0]).collect();
    assert!(hits(
        &compile_lines(&format!("$a = \"{value}\" wide\n")),
        &wide_data
    ));
    assert_eq!(
        matched(&compile_bounded(value, Family::Hostname), &wide_data),
        ["$b"]
    );
}

/// `test_bounded_modifiers_pick_the_strings`, its 4 rows.
#[test]
fn the_modifiers_pick_a_bounded_value_s_strings() {
    let config = ExportConfig {
        boundaries: [("url".to_owned(), "hostname".to_owned())].into(),
        ..config()
    };
    for (modifiers, expected) in [
        (
            "ascii wide nocase",
            vec![("$obsd_5", "ascii nocase"), ("$obsd_wide_5", "nocase")],
        ),
        ("ascii nocase", vec![("$obsd_5", "ascii nocase")]),
        ("nocase", vec![("$obsd_5", "ascii nocase")]),
        ("wide nocase", vec![("$obsd_wide_5", "nocase")]),
    ] {
        let Strings {
            lines: strings,
            identifiers: ids,
            ..
        } = format_strings_with(&config, &entry(5, "url", "evil.com"), modifiers);
        let got: Vec<(&str, &str)> = strings
            .lines()
            .map(|line| {
                (
                    line.split(" = ").next().unwrap().trim(),
                    line.rsplit_once('/').unwrap().1.trim(),
                )
            })
            .collect();
        assert_eq!(got, expected, "{modifiers}");
        assert_eq!(ids, expected.iter().map(|(id, _)| *id).collect::<Vec<_>>());
        let rules = compile_lines(&strings);
        assert_eq!(
            hits(&rules, b"see evil.com"),
            expected.contains(&("$obsd_5", "ascii nocase"))
        );
        assert_eq!(
            hits(&rules, &utf16("\u{feff}EVIL.COM")),
            expected.contains(&("$obsd_wide_5", "nocase"))
        );
    }
}

/// `test_bounded_drops_fullword`.
#[test]
fn a_bounded_string_drops_fullword() {
    let config = ExportConfig {
        boundaries: [("fqdn".to_owned(), "hostname".to_owned())].into(),
        ..config()
    };
    assert!(config.string_modifiers("fqdn").contains("fullword"));
    let line = format_strings(&config, &entry(7, "fqdn", "evil.example.com")).lines;
    assert!(line.trim().starts_with("$obsd_7 = /"), "{line}");
    assert!(!line.contains("fullword"));
    assert!(line.contains("$obsd_wide_7 = /"));
    let rules = compile_lines(&line);
    assert!(hits(&rules, b"a evil.example.com"));
    assert!(!hits(&rules, b"a-evil.example.com"));
}

/// `test_unbounded_type_unchanged`.
#[test]
fn a_type_with_no_boundary_keeps_its_text_string() {
    let config = ExportConfig {
        boundaries: [("url".to_owned(), "hostname".to_owned())].into(),
        ..config()
    };
    let subject = entry(9, "email_subject", "Invoice \"overdue\"");
    assert_eq!(
        config.string_boundary("email_subject", &subject.value),
        None
    );
    assert_eq!(
        format_strings(&config, &subject).lines,
        "          $obsd_9 = \"Invoice \\\"overdue\\\"\" ascii wide nocase\n"
    );
}

/// `test_no_boundary_config_keeps_text_strings`.
#[test]
fn no_boundaries_keeps_text_strings() {
    let config = ExportConfig {
        boundaries: BTreeMap::new(),
        ..config()
    };
    assert_eq!(
        format_strings_with(
            &config,
            &entry(3, "url", "evil-example.com"),
            "ascii wide nocase"
        )
        .lines,
        "          $obsd_3 = \"evil-example.com\" ascii wide nocase\n"
    );
}

/// `test_bounded_json_variant`.
#[test]
fn a_bounded_value_s_json_form_gets_its_own_strings() {
    let value = "http://bad.example.com/a\"b\\c";
    let Strings {
        lines: strings,
        identifiers: ids,
        ..
    } = format_strings_with(&config(), &entry(11, "url", value), "ascii wide nocase");
    assert_eq!(
        ids,
        [
            "$obsd_11",
            "$obsd_wide_11",
            "$obsd_json_11",
            "$obsd_json_wide_11"
        ]
    );
    let lines: Vec<&str> = strings.lines().collect();
    let raw = compile_lines(&format!("{}\n", lines[0]));
    assert!(hits(&raw, b"see http://bad.example.com/a\"b\\c here"));
    assert!(!hits(&raw, b"see http://bad.example.com/a\"b\\cd here"));
    assert!(hits(
        &compile_lines(&format!("{}\n", lines[1])),
        &utf16("see http://bad.example.com/a\"b\\c here")
    ));
    let json = "{\"u\":\"http://bad.example.com/a\\\"b\\\\c\"}";
    assert!(hits(
        &compile_lines(&format!("{}\n", lines[2])),
        json.as_bytes()
    ));
    assert!(hits(
        &compile_lines(&format!("{}\n", lines[3])),
        &utf16(json)
    ));
}

/// `test_bounded_long_value_keeps_text_string`. ace3's limit is libyara's, which stops a regex
/// about 1 KiB into a match; yara-x matches the longest bounded value too.
#[test]
fn a_long_value_keeps_its_text_string() {
    let prefix = "http://evil.example.com/";
    let value = format!(
        "{prefix}{}",
        "a".repeat(MAX_BOUNDED_VALUE_LENGTH - prefix.len())
    );
    assert_eq!(value.len(), MAX_BOUNDED_VALUE_LENGTH);
    let line = format_strings_with(&config(), &entry(1, "url", &value), "ascii wide nocase").lines;
    assert!(line.trim().starts_with("$obsd_1 = /"));
    let rules = compile_lines(&line);
    assert!(hits(&rules, format!("see {value}.").as_bytes()));
    // the longest wide boundary: a dot and then a code unit that isn't a word character
    assert!(hits(&rules, &utf16(&format!("\u{feff}{value}.\u{4e2d}"))));
    assert!(!hits(&rules, format!("x{value}").as_bytes()));
    assert!(!hits(&rules, &utf16(&format!("x{value}"))));

    let too_long = format!("{value}a");
    let line =
        format_strings_with(&config(), &entry(2, "url", &too_long), "ascii wide nocase").lines;
    assert_eq!(
        line,
        format!("          $obsd_2 = \"{too_long}\" ascii wide nocase\n")
    );
    assert!(hits(
        &compile_lines(&line),
        &utf16(&format!("see {too_long}."))
    ));
}

/// `test_unknown_boundary_family_falls_back`: ace3 logs the family at every export and keeps a
/// text string. Here the settings are refused when `ace serve` starts, and a family that got past
/// that still keeps the text string.
#[test]
fn an_unknown_boundary_family_is_refused_and_would_keep_the_text_string() {
    let config = ExportConfig {
        boundaries: [("url".to_owned(), "nonsense".to_owned())].into(),
        ..config()
    };
    let error = config.check().unwrap_err();
    assert!(
        error.contains("string_boundaries.url: \"nonsense\""),
        "{error}"
    );
    assert_eq!(config.string_boundary("url", "evil-example.com"), None);
    assert_eq!(
        format_strings_with(
            &config,
            &entry(4, "url", "evil-example.com"),
            "ascii wide nocase"
        )
        .lines,
        "          $obsd_4 = \"evil-example.com\" ascii wide nocase\n"
    );
}

/// `test_default_boundaries_name_known_families`, and the rest of ace3's defaults.
#[test]
fn the_defaults_are_ace3_s_and_pass_the_check() {
    let config = config();
    assert_eq!(config.boundaries["url"], "hostname");
    for family in config.boundaries.values() {
        assert!(family == "ip" || Family::parse(family).is_some());
    }
    assert_eq!(config.minimum_length, 5);
    assert_eq!(config.export_list.len(), 14);
    config.check().expect("ace3's settings");
}

/// `test_fingerprint_salt_tracks_the_string_config`, and the settings ace3's salt leaves out.
#[test]
fn the_fingerprint_tracks_the_settings() {
    let list = ExportList::new(vec![entry(1, "url", "evil-example.com")]);
    let bounded = fingerprint(&config(), &list);
    assert_ne!(bounded, list.fingerprint());
    assert_eq!(fingerprint(&config(), &list), bounded);

    let unbounded = ExportConfig {
        boundaries: BTreeMap::new(),
        ..config()
    };
    assert_ne!(fingerprint(&unbounded, &list), bounded);
    let modified = ExportConfig {
        modifiers: [("default".to_owned(), "ascii".to_owned())].into(),
        ..unbounded.clone()
    };
    assert_ne!(
        fingerprint(&modified, &list),
        fingerprint(&unbounded, &list)
    );
    // a template's text, which ace3's salt doesn't hold
    let mut templated = config();
    templated.templates.insert(
        "url".to_owned(),
        templated.templates["default"].replace("amber", "red"),
    );
    assert_ne!(fingerprint(&templated, &list), bounded);
}

// publishing

/// `test_export_writes_compilable_rules`.
#[test]
fn the_export_writes_rules_that_compile() {
    let export = generated(
        &config(),
        &[
            detection(4, "fqdn", "evil.example.com"),
            detection(9, "email_address", "attacker@example.com"),
        ],
    );
    let fqdn = rule_of(&export, "fqdn");
    assert!(fqdn.contains("$obsd_4 = /"));
    assert!(fqdn.contains("evil\\.example\\.com"));
    assert!(fqdn.contains("rule detect_fqdn : detect_fqdn"));
    assert!(fqdn.contains("date = \"11/15/2026\""));
    compile(fqdn);
    // email_address has a template of its own, which scopes the rule to the email's parts
    let email = rule_of(&export, "email_address");
    assert!(email.contains("$obsd_9"));
    assert!(email.contains("email.rfc822.headers"));
    compile(email);
    assert_eq!(
        export.report.types,
        [
            ExportedType {
                export_type: "email_address".to_owned(),
                detections: 1,
                strings: 2
            },
            ExportedType {
                export_type: "fqdn".to_owned(),
                detections: 1,
                strings: 2
            },
        ]
    );
    assert!(export.report.skipped.is_empty());
    assert_eq!(export.files.last().unwrap().name, INDEX_FILE);
}

/// `test_export_prunes_stale_rule_files`: a type with nothing left has no file. The builder's
/// half, a ruleset built again without it, is `ace-core`'s `rulesets` test.
#[test]
fn a_type_with_nothing_left_has_no_file() {
    let both = [
        detection(1, "fqdn", "evil.example.com"),
        detection(2, "email_address", "attacker@example.com"),
    ];
    assert!(has_file(&generated(&config(), &both), "fqdn"));
    let export = generated(&config(), &both[1..]);
    assert!(!has_file(&export, "fqdn"));
    assert!(has_file(&export, "email_address"));
    // and with no detection there's no file at all, the index included
    assert!(generated(&config(), &[]).files.is_empty());
}

/// `test_export_escapes_quotes_and_backslashes`.
#[test]
fn the_export_escapes_quotes_and_backslashes() {
    let export = generated(
        &config(),
        &[
            detection(7, "url", "http://bad.example.com/a\"b\\c"),
            detection(8, "email_subject", "Invoice \"a\\b\""),
        ],
    );
    // url is bounded, so it's a regex; a type with no boundary keeps the text string
    let url = rule_of(&export, "url");
    compile(url);
    assert!(
        url.contains("$obsd_7 = /(^|[^a-zA-Z0-9_\\-])http:\\/\\/bad\\.example\\.com\\/a\"b\\\\c("),
        "{url}"
    );
    // the json form differs, so it has a string of its own
    assert!(url.contains("$obsd_json_7 = /"));
    let subject = rule_of(&export, "email_subject");
    compile(subject);
    assert!(
        subject.contains("$obsd_8 = \"Invoice \\\"a\\\\b\\\"\""),
        "{subject}"
    );
    assert!(subject.contains("$obsd_json_8"));
}

/// `test_export_url_rule_does_not_match_inside_longer_host`, with the module's reading of the id
/// (`_parse_yara_string_key_id`) and the index the ruleset carries.
#[test]
fn a_url_s_rule_doesn_t_match_inside_a_longer_host_and_names_its_detection() {
    let export = generated(&config(), &[detection(42, "url", "evil-example.com")]);
    let rules = compile(rule_of(&export, "url"));
    assert!(!hits(&rules, b"(alice_smith@acme-evil-example.com)"));
    assert_eq!(
        matched(&rules, b"please block evil-example.com."),
        ["$obsd_42"]
    );
    // a UTF-16 hit is the wide string's, which names the same detection
    let wide = matched(&rules, &utf16("\u{feff}evil-example.com"));
    assert_eq!(wide, ["$obsd_wide_42"]);
    assert_eq!(string_id(&wide[0]), Some(42));
    for (name, id) in [
        ("$obsd_12", Some(12)),
        ("$obsd_json_12", Some(12)),
        ("$obsd_json_wide_12", Some(12)),
        ("$obsd_", None),
        ("$obsd_x", None),
        ("$obsd_-3", None),
        ("$obsd_0", None),
        // ace3's legacy strings name rows ace4 doesn't have
        ("$obs_12", None),
        ("$a", None),
    ] {
        assert_eq!(string_id(name), id, "{name}");
    }
    let ruleset = ruleset_of(&export);
    assert_eq!(ruleset.detection(42), Some(("url", "evil-example.com")));
    assert_eq!(ruleset.detection(43), None);
}

/// `test_export_applies_string_modifiers`.
#[test]
fn the_export_applies_each_type_s_modifiers() {
    let export = generated(
        &config(),
        &[
            detection(1, "fqdn", "evil.example.com"),
            detection(2, "ip", "192.168.44.100"),
            detection(3, "email_subject", "evil subject line"),
        ],
    );
    // fqdn is bounded: it drops fullword and has one string for ascii and one for wide
    let fqdn = rule_of(&export, "fqdn");
    assert!(fqdn.contains("/ ascii nocase"));
    assert!(fqdn.contains("$obsd_wide_"));
    assert!(!fqdn.contains("fullword"));
    // ip has no modifiers of its own, so it gets the default set
    let ip = rule_of(&export, "ip");
    assert!(ip.contains("/ ascii nocase"));
    assert!(ip.contains("$obsd_wide_"));
    assert!(!ip.contains("fullword"));
    assert!(rule_of(&export, "email_subject").contains("\"evil subject line\" ascii wide nocase"));
}

/// `test_export_handles_ipv4_ipv6_and_the_legacy_type`.
#[test]
fn the_export_handles_ipv4_ipv6_and_the_legacy_type() {
    let export = generated(
        &config(),
        &[
            detection(1, "ip", "192.168.44.100"),
            detection(2, "ip", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            detection(3, "ipv4", "10.20.30.40"),
        ],
    );
    // both address families are under the generic ip type
    let ip = rule_of(&export, "ip");
    compile(ip);
    assert!(ip.contains("$obsd_1 ") && ip.contains("$obsd_2 "));
    assert!(ip.contains("file_ext = \"!bmp\""));
    let legacy = rule_of(&export, "ipv4");
    compile(legacy);
    assert!(legacy.contains("$obsd_3 "));
}

/// `test_export_writes_subtype_detections_into_the_parent_rule_file`. The index keeps each
/// detection's own type, which is what ace3's scanner reads from its row.
#[test]
fn a_subtype_s_detections_are_in_the_parent_s_file() {
    let export = generated(
        &config(),
        &[
            detection(1, "email_reply_to", "reply@example.com"),
            detection(2, "email_address", "plain@example.com"),
        ],
    );
    let rule = rule_of(&export, "email_address");
    assert!(
        rule.contains("$obsd_1 ")
            && rule.contains("reply@example\\.com")
            && rule.contains("$obsd_2 ")
    );
    compile(rule);
    // the subtype has no file of its own: it has no template and isn't configured
    assert!(!has_file(&export, "email_reply_to"));
    let ruleset = ruleset_of(&export);
    assert_eq!(
        ruleset.detection(1),
        Some(("email_reply_to", "reply@example.com"))
    );
    assert_eq!(
        ruleset.detection(2),
        Some(("email_address", "plain@example.com"))
    );
}

/// `test_export_applies_parent_string_modifiers_to_subtypes`.
#[test]
fn a_subtype_takes_its_parent_s_modifiers_and_boundary() {
    let export = generated(
        &config(),
        &[detection(
            1,
            "email_dkim_signing_domain",
            "evil.example.com",
        )],
    );
    let rule = rule_of(&export, "fqdn");
    assert!(rule.contains("evil\\.example\\.com"));
    assert!(!rule.contains("fullword"));
    assert!(rule.contains("/(^|[^a-zA-Z0-9_\\-])evil"));
    assert!(!has_file(&export, "email_dkim_signing_domain"));
}

/// `test_export_falls_back_to_the_default_template`.
#[test]
fn a_type_without_a_template_takes_the_default() {
    let export = generated(
        &config(),
        &[detection(1, "user_agent", "Mozilla/4.0 (compatible; Evil)")],
    );
    let rule = rule_of(&export, "user_agent");
    assert!(rule.contains("rule detect_user_agent : detect_user_agent"));
    // the default template has no per-type meta
    assert!(!rule.contains("file_name"));
}

/// `test_export_survives_a_missing_template_dir`: a type with no template is skipped, here with
/// its detections reported, and the others are exported.
#[test]
fn a_type_with_no_template_is_skipped_and_reported() {
    let mut config = config();
    config.templates.remove("default");
    let export = generated(
        &config,
        &[
            detection(1, "fqdn", "evil.example.com"),
            detection(2, "ip", "192.168.44.100"),
        ],
    );
    assert!(!has_file(&export, "fqdn"));
    assert!(has_file(&export, "ip"));
    assert_eq!(
        export.report.skipped,
        [Skipped {
            id: 1,
            export_type: "fqdn".to_owned(),
            error: "no template".to_owned()
        }]
    );
    // and the settings say so when `ace serve` starts
    assert!(
        config
            .check()
            .unwrap_err()
            .contains("templates has none for")
    );
}

// what ace3's tests don't have: the values are hostile input to a rule compiler

/// Values written to break out of a string, a regex, a rule or the template. Each is exported as
/// the bytes it is, and the rule holds what its template holds and nothing else.
#[test]
fn a_hostile_value_is_only_ever_a_string() {
    let hostile = [
        "x\" condition: true } rule injected { condition: true } rule y { strings: $a = \"",
        "x/ condition: true } rule injected { condition: true } //",
        "evil.example.com\"\n    condition:\n        true\n}\nrule injected { condition: true }",
        "*/ rule injected { condition: true } /*",
        "trailing backslash \\",
        "\\\" still inside",
        "TEMPLATE_STRINGS TEMPLATE_RULE_NAME TEMPLATE_DATE_STRING",
        "$obsd_999 = \"other\"",
        "include \"/etc/passwd\"",
        "import \"pe\" {{{{ }}}} [[[[ (((( ????",
        "caf\u{e9} \u{2028}line\u{2029} \u{202e}rtl \u{1f600}",
        "tab\there \u{1}\u{7f}\u{1b}[31m",
    ];
    let mut detections = Vec::new();
    for (index, value) in hostile.iter().enumerate() {
        // once as a text string, once as a bounded regex
        detections.push(detection(index as i64 * 2 + 1, "email_subject", value));
        detections.push(detection(index as i64 * 2 + 2, "url", value));
    }
    let export = generated(&config(), &detections);
    assert_eq!(export.report.skipped, [], "nothing here is refused");
    assert_eq!(export.report.exported(), detections.len());
    assert_eq!(
        export
            .files
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        ["email_subject.yar", "url.yar", INDEX_FILE]
    );
    let ruleset = ruleset_of(&export);
    let names: BTreeSet<String> = ruleset
        .rules()
        .iter()
        .map(|r| r.identifier().to_owned())
        .collect();
    assert_eq!(
        names.iter().map(String::as_str).collect::<Vec<_>>(),
        ["detect_email_subject", "detect_url", INDEX_RULE]
    );
    for d in &detections {
        assert_eq!(
            ruleset.detection(d.id),
            Some((d.observable_type.as_str(), d.value.as_str()))
        );
    }
    // each value matches itself, by its own id, and nothing matches unrelated text
    for name in ["email_subject", "url"] {
        let rules = compile(rule_of(&export, name));
        assert!(!hits(
            &rules,
            b"nothing to see here: condition true rule injected"
        ));
        for d in detections.iter().filter(|d| d.observable_type == name) {
            let data = format!(" {} ", d.value.replace(['\n', '\r'], ""));
            let ids: Vec<Option<i64>> = matched(&rules, data.as_bytes())
                .iter()
                .map(|m| string_id(m))
                .collect();
            assert!(ids.contains(&Some(d.id)), "{:?} matched {ids:?}", d.value);
        }
    }
}

/// A value the compiler refuses leaves out only itself, and says why. Nothing ace3's escaping lets
/// through is refused by yara-x, so the refusal here is the structure check's: a template that
/// puts the strings where a value can change the rule.
#[test]
fn a_refused_value_fails_only_its_own_entry() {
    let mut config = config();
    // a template that (wrongly) writes the strings into a place a quote ends
    config.templates.insert(
        "user_agent".to_owned(),
        "rule detect_TEMPLATE_RULE_NAME {\n  strings:\nTEMPLATE_STRINGS\n  condition:\n    any of ($obsd_*)\n}\n"
            .to_owned(),
    );
    config.check().expect("the template compiles");
    // a value over the bound, and one holding a NUL, which a list refuses and this doesn't trust
    let long = "a".repeat(MAX_VALUE_BYTES + 1);
    let export = generated(
        &config,
        &[
            detection(1, "user_agent", "Mozilla/4.0 (compatible; Evil)"),
            detection(2, "user_agent", &long),
            detection(3, "user_agent", "nul\0inside"),
            detection(4, "user_agent", "Another/1.0 agent"),
        ],
    );
    assert_eq!(
        export.report.skipped,
        [
            Skipped {
                id: 2,
                export_type: "user_agent".to_owned(),
                error: format!("the value is over {MAX_VALUE_BYTES} bytes")
            },
            Skipped {
                id: 3,
                export_type: "user_agent".to_owned(),
                error: "the value holds a NUL character".to_owned()
            },
        ]
    );
    let rule = rule_of(&export, "user_agent");
    assert!(rule.contains("$obsd_1 ") && rule.contains("$obsd_4 ") && !rule.contains("$obsd_2 "));
    let ruleset = ruleset_of(&export);
    assert_eq!(
        ruleset.detection(1).map(|d| d.1),
        Some("Mozilla/4.0 (compatible; Evil)")
    );
    assert_eq!(ruleset.detection(2), None);
    assert_eq!(ruleset.detection(3), None);
}

/// The structure check itself: strings that compile but change what the rule holds are refused
/// one entry at a time, as a compile error is.
#[test]
fn strings_that_change_the_rule_s_structure_are_refused() {
    let template = config().template("fqdn", "01/01/2000").unwrap();
    let expected = shape(&template.replace(TEMPLATE_STRINGS, PROBE_LINE)).unwrap();
    let ok = ("          $obsd_1 = \"evil\"\n", vec!["$obsd_1".to_owned()]);
    check_rule(&template, &expected, ok.0, &ok.1).expect("the strings the export wrote");
    for (strings, why) in [
        // one more string than the export wrote
        (
            "          $obsd_1 = \"evil\"\n          $obsd_2 = \"more\"\n",
            "structure",
        ),
        // a second rule
        (
            "          $obsd_1 = \"evil\"\n    condition: $obsd_1 }\nrule injected { strings: $obsd_9 = \"x\"\n",
            "structure",
        ),
        // a changed meta
        (
            "          $obsd_1 = \"evil\"\n    meta: x = 1\n    strings: $obsd_2 = \"y\"\n",
            "",
        ),
        // not a string at all
        ("          $obsd_1 = \"unterminated\n", ""),
    ] {
        let error = check_rule(&template, &expected, strings, &ok.1).unwrap_err();
        assert!(error.contains(why), "{strings:?}: {error}");
    }
}

/// The bounds: `MAX_ENTRIES` detections and `MAX_SOURCE_BYTES` of rule text, the rest reported.
#[test]
fn the_export_is_bounded() {
    let config = ExportConfig {
        minimum_length: 1,
        ..config()
    };
    let detections: Vec<Detection> = (1..=MAX_ENTRIES as i64 + 3)
        .map(|id| detection(id, "email_subject", &format!("subject number {id}")))
        .collect();
    let export = generated(&config, &detections);
    assert_eq!(export.report.exported(), MAX_ENTRIES);
    assert_eq!(export.report.skipped.len(), 3);
    assert_eq!(
        export.report.skipped[0],
        Skipped {
            id: MAX_ENTRIES as i64 + 1,
            export_type: "email_subject".to_owned(),
            error: format!("an export holds at most {MAX_ENTRIES} detections")
        }
    );
    assert_eq!(
        ruleset_of(&export)
            .detection(MAX_ENTRIES as i64)
            .map(|d| d.0),
        Some("email_subject")
    );

    // the longest values a list holds: the index holds each again in hex, so they don't all fit
    let detections: Vec<Detection> = (1..=MAX_ENTRIES as i64)
        .map(|id| {
            detection(
                id,
                "email_subject",
                &format!("{id:0>width$}", width = MAX_VALUE_BYTES),
            )
        })
        .collect();
    let started = std::time::Instant::now();
    let export = generated(&config, &detections);
    let total: usize = export.files.iter().map(|f| f.source.len()).sum();
    println!(
        "{} of {MAX_ENTRIES} values of {MAX_VALUE_BYTES} bytes: {total} bytes of rules in {:?}",
        export.report.exported(),
        started.elapsed()
    );
    assert!(total <= MAX_SOURCE_BYTES + (64 << 10), "{total}");
    assert!(export.report.exported() < MAX_ENTRIES && export.report.exported() > 500);
    assert_eq!(
        export.report.exported() + export.report.skipped.len(),
        MAX_ENTRIES
    );
    assert_eq!(
        export.report.skipped.last().unwrap().error,
        format!("the export's rules are at most {MAX_SOURCE_BYTES} bytes")
    );
}

/// yara-x's parser recurses once for each escape in a literal, and a few thousand overflow the
/// stack, which no caller can catch. So a string holds at most `MAX_ESCAPES`: a value whose text
/// string would hold more is left out, and a bounded value whose regex would keeps its text
/// string. The test runs on the 2 MiB stack a blocking thread of the core's runtime has.
#[test]
fn a_value_of_escapes_can_t_overflow_the_compiler_s_stack() {
    let work = || {
        let config = ExportConfig {
            minimum_length: 1,
            ..config()
        };
        let backslashes = "\\".repeat(MAX_VALUE_BYTES);
        let quotes = "\"".repeat(MAX_VALUE_BYTES);
        // 500 characters, most of four bytes each: about 4,000 escapes as a wide regex
        let astral = "\u{1f600}".repeat(MAX_BOUNDED_VALUE_LENGTH - 20) + "evil.example.com/a.b.";
        // the most a text string may hold: its JSON form doubles each backslash
        let most = format!("{}most", "\\".repeat(MAX_ESCAPES / 2));
        let over = format!("{}over", "\\".repeat(MAX_ESCAPES / 2 + 1));
        let export = generated(
            &config,
            &[
                detection(1, "email_subject", &backslashes),
                detection(2, "email_subject", &quotes),
                detection(3, "url", &backslashes),
                detection(4, "url", &astral),
                detection(5, "email_subject", &most),
                detection(6, "email_subject", &over),
                detection(7, "url", "http://fine.example.com/"),
            ],
        );
        let error =
            format!("the value holds more than {MAX_ESCAPES} characters a rule has to escape");
        assert_eq!(
            export
                .report
                .skipped
                .iter()
                .map(|s| (s.id, s.error.as_str()))
                .collect::<Vec<_>>(),
            [
                (1, error.as_str()),
                (2, error.as_str()),
                (6, error.as_str()),
                (3, error.as_str())
            ]
        );
        // the astral value is a text string, which matches it as the wide modifier does
        let url = rule_of(&export, "url");
        assert!(
            url.contains(&format!("$obsd_4 = \"{astral}\" ascii wide nocase")),
            "{url}"
        );
        assert!(url.contains("$obsd_7 = /"));
        let rules = compile(url);
        assert_eq!(
            matched(&rules, format!(" {astral} ").as_bytes()),
            ["$obsd_4"]
        );
        let rules = compile(rule_of(&export, "email_subject"));
        assert_eq!(matched(&rules, most.as_bytes()), ["$obsd_5"]);
        assert_eq!(
            format_strings(&config, &entry(5, "email_subject", &most)).escapes,
            MAX_ESCAPES
        );
    };
    std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(work)
        .unwrap()
        .join()
        .unwrap();
}

/// Two types whose templates give their rules one name don't load together, so nothing is
/// exported and the report says why; the ruleset's own build is never handed them.
#[test]
fn files_that_don_t_load_together_export_nothing() {
    let mut config = config();
    let fixed =
        "rule detect_same {\n  strings:\nTEMPLATE_STRINGS\n  condition:\n    any of ($obsd_*)\n}\n";
    config.templates.insert("fqdn".to_owned(), fixed.to_owned());
    config.templates.insert("url".to_owned(), fixed.to_owned());
    config.check().expect("each compiles alone");
    let export = generated(
        &config,
        &[
            detection(1, "fqdn", "evil.example.com"),
            detection(2, "url", "evil-example.com"),
        ],
    );
    assert!(export.files.is_empty());
    assert!(export.report.types.is_empty());
    assert!(
        export
            .report
            .error
            .as_deref()
            .is_some_and(|e| e.contains("detect_same")),
        "{:?}",
        export.report
    );
    assert_eq!(
        export
            .report
            .skipped
            .iter()
            .map(|s| s.id)
            .collect::<Vec<_>>(),
        [1, 2]
    );
}

/// The settings' check: what the overlay can get wrong.
#[test]
fn the_settings_are_checked() {
    let bad = |change: fn(&mut ExportConfig)| {
        let mut config = config();
        change(&mut config);
        config.check().unwrap_err()
    };
    assert!(bad(|c| c.export_list.push("fq dn".to_owned())).contains("export_list"));
    assert!(bad(|c| c.export_list.push("../x".to_owned())).contains("export_list"));
    assert!(
        bad(|c| drop(
            c.modifiers
                .insert("fqdn".to_owned(), "ascii\" condition: true".to_owned())
        ))
        .contains("string_modifiers.fqdn")
    );
    assert!(
        bad(|c| drop(c.modifiers.insert("fqdn".to_owned(), "xor".to_owned()))).contains("\"xor\"")
    );
    assert!(
        bad(|c| drop(
            c.templates
                .insert("fqdn".to_owned(), "rule x { condition: true }".to_owned())
        ))
        .contains("TEMPLATE_STRINGS once")
    );
    assert!(
        bad(|c| drop(
            c.templates
                .insert("fqdn".to_owned(), "rule x { TEMPLATE_STRINGS".to_owned())
        ))
        .contains("doesn't compile")
    );
    assert!(
        bad(|c| drop(
            c.templates
                .insert("fqdn".to_owned(), "x".repeat(MAX_TEMPLATE_BYTES + 1))
        ))
        .contains("bytes")
    );
    assert!(
        bad(|c| drop(
            c.templates
                .insert("no/pe".to_owned(), "TEMPLATE_STRINGS".to_owned())
        ))
        .contains("templates")
    );
}

/// An index rule in another namespace, or one that isn't the export's shape, names nothing.
#[test]
fn only_the_export_s_index_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let write = |namespace: &str, source: &str| {
        let path = dir.path().join(namespace);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("index.yar"), source).unwrap();
    };
    // "url" and "x" in hex
    write(
        "elsewhere",
        "rule obsd_index { meta: e1 = \"75726c:78\" condition: false }",
    );
    let loaded = crate::load_dir(dir.path(), &crate::LoadOptions::default()).unwrap();
    assert_eq!(loaded.ruleset.detection(1), None);
    write(
        NAMESPACE,
        "rule obsd_index { meta: e1 = \"75726c:78\" e2 = \"zz:78\" e3 = 5 x4 = \"75726c:78\" e5 = \"75726c\" \
         e6 = \"ff:78\" condition: false }",
    );
    let loaded = crate::load_dir(dir.path(), &crate::LoadOptions::default()).unwrap();
    assert_eq!(loaded.ruleset.detection(1), Some(("url", "x")));
    for id in 2..=6 {
        assert_eq!(loaded.ruleset.detection(id), None, "{id}");
    }
}
