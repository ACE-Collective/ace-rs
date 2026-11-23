//! What the module reads from splunkd's REST API, and the paths it asks for, as splunk-sdk
//! (splunklib 3.0.1, which ace3's `saq/splunk.py` drives) builds and parses them.

use serde_json::{Map, Value};

/// The search job endpoint: v2 from Splunk 9.0.2 on (9.0.2209 on Splunk Cloud), v1 before, as
/// splunklib's `Service.disable_v2_api` decides.
pub(crate) fn jobs_path(info: &Map<String, Value>) -> &'static str {
    let version: Vec<u64> = info
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect();
    let cloud = info
        .get("instance_type")
        .and_then(Value::as_str)
        .is_some_and(|t| t.eq_ignore_ascii_case("cloud"));
    let v2_from: &[u64] = if cloud { &[9, 0, 2209] } else { &[9, 0, 2] };
    if version.as_slice() < v2_from {
        "search/jobs"
    } else {
        "search/v2/jobs"
    }
}

/// The path prefix of a namespace, as splunklib's `_abspath`: `/services` when neither the owner
/// nor the app is set, otherwise `/servicesNS/<owner or nobody>/<app or system>`.
pub(crate) fn namespace(owner: Option<&str>, app: Option<&str>) -> String {
    if owner.is_none() && app.is_none() {
        return "/services".to_owned();
    }
    format!(
        "/servicesNS/{}/{}",
        segment(owner.unwrap_or("nobody")),
        segment(app.unwrap_or("system"))
    )
}

/// The namespace splunklib uses for a job once it has read the job's `eai:acl`: a job shared
/// `global` or `app` belongs to `nobody` in its app, one shared `system` to `nobody/system`, and
/// any other to its owner. Without an acl, the client's own namespace.
pub(crate) fn job_namespace(acl: Option<&Value>, fallback: &str) -> String {
    let Some(acl) = acl else {
        return fallback.to_owned();
    };
    let owner = acl.get("owner").and_then(Value::as_str);
    let app = acl.get("app").and_then(Value::as_str);
    match acl.get("sharing").and_then(Value::as_str) {
        Some("system") => namespace(Some("nobody"), Some("system")),
        Some("global" | "app") => namespace(Some("nobody"), app),
        _ => namespace(owner, app),
    }
}

/// A path segment, percent-encoded outside the characters a URL path allows unescaped.
pub(crate) fn segment(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~:@".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A form body, `application/x-www-form-urlencoded`.
pub(crate) fn form(pairs: &[(&str, &str)]) -> String {
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// The text of the first element named `name`, such as a login's `sessionKey` or a new job's
/// `sid`.
pub(crate) fn element_text(xml: &str, name: &str) -> Option<String> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    doc.descendants()
        .find(|n| n.is_element() && n.tag_name().name() == name)
        .map(|n| n.text().unwrap_or_default().trim().to_owned())
}

/// The messages of an error response, such as `Unknown search command 'foo'.`, one per line.
pub(crate) fn messages(xml: &str) -> Option<String> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let texts: Vec<&str> = doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name() == "msg")
        .filter_map(|n| n.text())
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect();
    (!texts.is_empty()).then(|| texts.join("\n"))
}

/// The first Atom entry's content, as a map: the job's status, or the server's info. splunkd
/// answers a job with an `<entry>` and the server info with a `<feed>` holding one.
pub(crate) fn entry_content(xml: &str) -> Result<Map<String, Value>, String> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| format!("unreadable XML: {e}"))?;
    let content = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "content")
        .ok_or("no <content> in the response")?;
    let dict = content
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "dict")
        .ok_or("no <s:dict> in the response's <content>")?;
    match s_dict(dict) {
        Value::Object(map) => Ok(map),
        _ => Err("the response's <s:dict> isn't a dict".to_owned()),
    }
}

/// An `<s:dict>` as an object, its `<s:key>`s by name.
fn s_dict(node: roxmltree::Node) -> Value {
    Value::Object(
        node.children()
            .filter(|n| n.is_element() && n.tag_name().name() == "key")
            .map(|key| {
                (
                    key.attribute("name").unwrap_or_default().to_owned(),
                    s_value(key),
                )
            })
            .collect(),
    )
}

/// A key's or an item's value: a nested `<s:dict>`, an `<s:list>`, or its text.
fn s_value(node: roxmltree::Node) -> Value {
    match node.children().find(|n| n.is_element()) {
        Some(child) if child.tag_name().name() == "dict" => s_dict(child),
        Some(child) if child.tag_name().name() == "list" => Value::Array(
            child
                .children()
                .filter(|n| n.is_element() && n.tag_name().name() == "item")
                .map(s_value)
                .collect(),
        ),
        _ => Value::String(node.text().unwrap_or_default().to_owned()),
    }
}

/// The rows of a job's results with `output_mode=json`: one JSON object per line, each with a
/// `results` list (splunklib's `JSONResultsReader`). Splunk's own messages are logged.
pub(crate) fn result_rows(body: &[u8]) -> Result<Vec<Map<String, Value>>, String> {
    let mut rows = Vec::new();
    for document in serde_json::Deserializer::from_slice(body).into_iter::<Value>() {
        let document = document.map_err(|e| format!("unreadable results: {e}"))?;
        for message in document["messages"].as_array().into_iter().flatten() {
            tracing::info!(
                "splunk message ({}): {}",
                message["type"].as_str().unwrap_or_default(),
                message["text"].as_str().unwrap_or_default()
            );
        }
        for row in document["results"].as_array().into_iter().flatten() {
            if let Value::Object(row) = row {
                rows.push(row.clone());
            }
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn info(version: &str, instance_type: Option<&str>) -> Map<String, Value> {
        let mut info = Map::new();
        info.insert("version".to_owned(), json!(version));
        if let Some(t) = instance_type {
            info.insert("instance_type".to_owned(), json!(t));
        }
        info
    }

    #[test]
    fn the_v2_search_api_starts_at_9_0_2() {
        assert_eq!(jobs_path(&info("9.0.1", None)), "search/jobs");
        assert_eq!(jobs_path(&info("9.0.2", None)), "search/v2/jobs");
        assert_eq!(jobs_path(&info("9.3.2", None)), "search/v2/jobs");
        assert_eq!(jobs_path(&info("10.0", None)), "search/v2/jobs");
        assert_eq!(jobs_path(&info("9.0.2208", Some("cloud"))), "search/jobs");
        assert_eq!(
            jobs_path(&info("9.1.2308", Some("cloud"))),
            "search/v2/jobs"
        );
    }

    #[test]
    fn namespaces_follow_splunklib() {
        assert_eq!(namespace(None, None), "/services");
        assert_eq!(namespace(Some("ace"), None), "/servicesNS/ace/system");
        assert_eq!(namespace(None, Some("search")), "/servicesNS/nobody/search");
        let acl = json!({"owner": "ace-rs", "app": "search", "sharing": "global"});
        assert_eq!(
            job_namespace(Some(&acl), "/services"),
            "/servicesNS/nobody/search"
        );
        let acl = json!({"owner": "ace-rs", "app": "search", "sharing": "user"});
        assert_eq!(
            job_namespace(Some(&acl), "/services"),
            "/servicesNS/ace-rs/search"
        );
        let acl = json!({"owner": "ace-rs", "app": "search", "sharing": "system"});
        assert_eq!(
            job_namespace(Some(&acl), "/services"),
            "/servicesNS/nobody/system"
        );
        assert_eq!(job_namespace(None, "/services"), "/services");
    }

    #[test]
    fn a_job_entry_reads_as_a_map() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<entry xmlns="http://www.w3.org/2005/Atom" xmlns:s="http://dev.splunk.com/ns/rest">
  <title>search index=x</title>
  <content type="text/xml">
    <s:dict>
      <s:key name="dispatchState">RUNNING</s:key>
      <s:key name="eai:acl">
        <s:dict>
          <s:key name="owner">ace-rs</s:key>
          <s:key name="perms"><s:dict><s:key name="read"><s:list><s:item>ace-rs</s:item></s:list></s:key></s:dict></s:key>
        </s:dict>
      </s:key>
      <s:key name="label"></s:key>
    </s:dict>
  </content>
</entry>"#;
        let content = entry_content(xml).expect("parses");
        assert_eq!(content["dispatchState"], json!("RUNNING"));
        assert_eq!(content["eai:acl"]["owner"], json!("ace-rs"));
        assert_eq!(content["eai:acl"]["perms"]["read"], json!(["ace-rs"]));
        assert_eq!(content["label"], json!(""));
    }

    #[test]
    fn error_messages_are_read() {
        let xml = r#"<response><messages><msg type="FATAL">Unknown search command 'foo'.</msg></messages></response>"#;
        assert_eq!(
            messages(xml).as_deref(),
            Some("Unknown search command 'foo'.")
        );
        assert_eq!(
            element_text("<response><sid>1.2</sid></response>", "sid").as_deref(),
            Some("1.2")
        );
    }

    #[test]
    fn results_on_several_lines_are_joined() {
        let body =
            br#"{"preview":false,"messages":[{"type":"INFO","text":"hi"}],"results":[{"a":"1"}]}
{"preview":false,"messages":[],"results":[{"a":"2"},{"a":["3","4"]}]}"#;
        let rows = result_rows(body).expect("parses");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[2]["a"], json!(["3", "4"]));
        assert!(result_rows(b"").expect("empty is no rows").is_empty());
    }

    #[test]
    fn segments_are_escaped() {
        assert_eq!(segment("1767225600.1"), "1767225600.1");
        assert_eq!(
            segment("admin__admin__search__RMD5a b/c"),
            "admin__admin__search__RMD5a%20b%2Fc"
        );
    }
}
