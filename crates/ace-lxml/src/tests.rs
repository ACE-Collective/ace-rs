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
