use super::*;

#[test]
fn parses_and_serializes_as_lxml() {
    let doc = Document::parse_html("<p>caf\u{e9} <!-- c --></p>".as_bytes()).unwrap();
    assert_eq!(
        doc.tostring_html().unwrap(),
        "<html><body><p>caf\u{e9} <!-- c --></p></body></html>"
    );
}

#[test]
fn soup_text_leaves_out_scripts_and_collapses_blank_strings() {
    let text =
        soup::get_text("<p>a <b>b</b></p>\n\n<script>x</script><pre>  </pre><!-- c -->d").unwrap();
    assert_eq!(text, "a b\n  d");
}

/// One node as `tests/data/soup_cases.py` writes bs4's.
fn node_json(tree: &soup::Tree, index: usize) -> serde_json::Value {
    use serde_json::json;
    match tree.node(index) {
        soup::Node::Element { name, attrs } => {
            let attrs: Vec<_> = attrs
                .iter()
                .map(|(k, v)| match v {
                    soup::AttrValue::Text(text) => json!([k, text]),
                    soup::AttrValue::List(parts) => json!([k, parts]),
                })
                .collect();
            json!({
                "tag": name,
                "attrs": attrs,
                "string": tree.string(index),
                "own": tree.own_string(index),
            })
        }
        soup::Node::Text { text, kind } => {
            let kind = match kind {
                soup::StringKind::Plain => "plain",
                soup::StringKind::Container => "container",
                soup::StringKind::Comment => "comment",
                soup::StringKind::ProcessingInstruction => "pi",
                soup::StringKind::Doctype => "doctype",
            };
            json!({"kind": kind, "text": text})
        }
        soup::Node::Document => json!("document"),
    }
}

#[test]
fn soup_trees_match_beautifulsoup() {
    use base64::Engine;
    let cases: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(include_str!("../tests/data/soup_cases.json"))
            .expect("the cases read");
    assert!(cases.len() >= 700);
    let mut failed = Vec::new();
    for (name, case) in &cases {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(case["input"].as_str().expect("input"))
            .expect("base64");
        let text = ace_pycompat::pystr::decode_utf8_ignore(&bytes);
        let got = soup::parse(&text).map(|tree| {
            serde_json::Value::Array((1..tree.len()).map(|i| node_json(&tree, i)).collect())
        });
        let got = got.unwrap_or(serde_json::Value::Null);
        if got != case["nodes"] {
            failed.push(format!("{name}: expected {}\n got {}", case["nodes"], got));
        }
    }
    assert!(
        failed.is_empty(),
        "{} differ:\n{}",
        failed.len(),
        failed.join("\n")
    );
}

/// lxml's target calls, as `tests/data/target_cases.py` writes them.
#[derive(Default)]
struct Recorder(Vec<serde_json::Value>);

impl target::Target for Recorder {
    fn start(&mut self, tag: &str, attrib: &[(String, String)]) {
        let attrib: Vec<_> = attrib
            .iter()
            .map(|(k, v)| serde_json::json!([k, v]))
            .collect();
        self.0.push(serde_json::json!(["start", tag, attrib]));
    }
    fn end(&mut self, tag: &str) {
        self.0.push(serde_json::json!(["end", tag]));
    }
    fn data(&mut self, text: &str) {
        if let Some(last) = self.0.last_mut()
            && last[0] == "data"
        {
            let joined = format!("{}{text}", last[1].as_str().unwrap_or(""));
            last[1] = serde_json::Value::String(joined);
            return;
        }
        self.0.push(serde_json::json!(["data", text]));
    }
}

#[test]
fn target_events_match_lxml() {
    use base64::Engine;
    let cases: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(include_str!("../tests/data/target_cases.json"))
            .expect("the cases read");
    assert!(cases.len() >= 450);
    let mut failed = Vec::new();
    for (name, case) in &cases {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(case["input"].as_str().expect("input"))
            .expect("base64");
        let mut recorder = Recorder::default();
        let raised = target::parse(&bytes, &mut recorder).is_err();
        let events = serde_json::Value::Array(recorder.0);
        if events != case["events"] || serde_json::Value::Bool(raised) != case["raised"] {
            failed.push(format!(
                "{name}: expected {} raised {}\n got {events} raised {raised}",
                case["events"], case["raised"]
            ));
        }
    }
    assert!(
        failed.is_empty(),
        "{} differ:\n{}",
        failed.len(),
        failed.join("\n")
    );
}
