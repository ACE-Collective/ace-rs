//! Each way an include, or a rule file, could reach outside its signature directory, and what the
//! loader says of it: never a byte of the file.

use std::path::{Path, PathBuf};

use super::*;
use crate::load::{FileOutcome, LoadOptions, load_dir, new_compiler};

/// What must never appear in a report: the first line of the file outside.
const SECRET: &str = "SECRET-TOKEN-hunter2";

/// A signature directory `sigs` with the namespaces `a` and `b`, beside a directory `outside` that
/// holds a file that isn't YARA and one that is.
struct Tree {
    dir: tempfile::TempDir,
}

impl Tree {
    fn new() -> Tree {
        let tree = Tree {
            dir: tempfile::tempdir().expect("a directory"),
        };
        tree.write("sigs/b/d.yar", "rule in_b { condition: true }\n");
        tree.write("outside/secret.txt", &format!("{SECRET} not a rule\n"));
        tree.write("outside/ok.yar", "rule outside_rule { condition: true }\n");
        std::fs::create_dir_all(tree.path("sigs/a")).expect("a namespace");
        tree
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.dir.path().join(relative)
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.path(relative);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("directories");
        std::fs::write(path, text).expect("writes");
    }

    fn link(&self, target: &str, relative: &str) {
        std::os::unix::fs::symlink(target, self.path(relative)).expect("links");
    }

    /// What became of `sigs/a/<name>` when the signature directory loads: its rules' names, or why
    /// it was left out.
    fn outcome(&self, name: &str) -> Result<Vec<String>, String> {
        let loaded = load_dir(&self.path("sigs"), &LoadOptions::default()).expect("loads");
        let wanted = self.path("sigs/a").join(name);
        let report = loaded
            .files
            .iter()
            .find(|file| file.path == wanted)
            .unwrap_or_else(|| panic!("no report for {name}"));
        match &report.outcome {
            FileOutcome::Included { rules } => Ok(rules.iter().map(|r| r.name.clone()).collect()),
            FileOutcome::LeftOut { error } => Err(error.clone()),
        }
    }

    /// `sigs/a/probe.yar` holding `source`, loaded.
    fn probe(&self, source: &str) -> Result<Vec<String>, String> {
        self.write("sigs/a/probe.yar", source);
        self.outcome("probe.yar")
    }

    fn boundary(&self) -> Boundary {
        Boundary::of_namespace(&self.path("sigs/a"))
    }

    fn resolve(&self, source: &str) -> Result<Resolved, Refusal> {
        self.boundary().resolve(
            &self.path("sigs/a"),
            &self.path("sigs/a/probe.yar"),
            source.as_bytes(),
        )
    }
}

fn refused(result: Result<Vec<String>, String>) -> String {
    let error = result.expect_err("the file is left out");
    assert!(
        !error.contains(SECRET),
        "the report quotes the file: {error}"
    );
    assert!(
        !error.contains("root:"),
        "the report quotes /etc/passwd: {error}"
    );
    error
}

/// An include of another namespace's file, in the same signature directory, still compiles: ace3's
/// working rule, and what the probe that found this did.
#[test]
fn an_include_reaches_another_namespace_of_its_signature_directory() {
    let tree = Tree::new();
    assert_eq!(
        tree.probe("include \"../b/d.yar\"\nrule a1 { condition: in_b }\n"),
        Ok(vec!["in_b".to_owned(), "a1".to_owned()])
    );
    // and a file of its own namespace, with or without `./`, in a directory of it too
    tree.write("sigs/a/common.inc", "rule common { condition: true }\n");
    tree.write("sigs/a/lib/deep.inc", "include \"common.inc\"\n");
    assert_eq!(
        tree.probe("include \"./common.inc\"\nrule a2 { condition: common }\n"),
        Ok(vec!["common".to_owned(), "a2".to_owned()])
    );
    // an included file's own include is looked for beside it, then in the namespace's directory
    assert_eq!(
        tree.probe("include \"lib/deep.inc\"\nrule a3 { condition: common }\n"),
        Ok(vec!["common".to_owned(), "a3".to_owned()])
    );
}

/// `../` out of the signature directory: refused by the path's text, whether or not a file is there,
/// so the answer doesn't say which.
#[test]
fn a_relative_include_can_not_leave_the_signature_directory() {
    let tree = Tree::new();
    let mut answers = Vec::new();
    for path in [
        "../../outside/secret.txt",
        "../../outside/ok.yar",
        "../../outside/no-such-file",
        "../../../../../../../../etc/passwd",
        "../b/../../outside/secret.txt",
        "./../../outside/secret.txt",
        "../..",
        "../../",
    ] {
        let error = refused(tree.probe(&format!(
            "include \"{path}\"\nrule r {{ condition: true }}\n"
        )));
        assert!(
            error.contains("leaves the signature directory"),
            "{path}: {error}"
        );
        answers.push(error.replace(path, "PATH"));
    }
    // a file that is there and one that isn't read the same
    assert_eq!(answers[0], answers[2]);
    // the valid rule file outside isn't compiled in either
    let loaded = load_dir(&tree.path("sigs"), &LoadOptions::default()).expect("loads");
    assert!(loaded.rules().all(|rule| rule.name != "outside_rule"));
}

/// An absolute path: `/etc/passwd`, the process's own environment, a secrets file, another
/// checkout. Refused wherever it points, even into the signature directory.
#[test]
fn an_absolute_include_is_refused() {
    let tree = Tree::new();
    let inside = tree.path("sigs/b/d.yar");
    let secret = tree.path("outside/secret.txt");
    for path in [
        "/etc/passwd",
        "/proc/self/environ",
        "/run/secrets/token",
        secret.to_str().expect("text"),
        inside.to_str().expect("text"),
        "//etc/passwd",
    ] {
        let error = refused(tree.probe(&format!(
            "include \"{path}\"\nrule r {{ condition: true }}\n"
        )));
        assert!(error.contains("an absolute path"), "{path}: {error}");
    }
}

/// A symbolic link in the repository that points out of it: as the included file, on the way to it,
/// as the rule file itself, and as the namespace's directory. None is followed.
#[test]
fn a_symbolic_link_is_not_followed() {
    let tree = Tree::new();
    tree.link("../../outside/secret.txt", "sigs/a/link.inc");
    tree.link("../../outside", "sigs/a/linked");
    // even one that stays inside: the ruleset build exports no link, so it could only work elsewhere
    tree.link("../b/d.yar", "sigs/a/inside.inc");
    for path in [
        "link.inc",
        "linked/secret.txt",
        "linked/ok.yar",
        "inside.inc",
    ] {
        let error = refused(tree.probe(&format!(
            "include \"{path}\"\nrule r {{ condition: true }}\n"
        )));
        assert!(error.contains("symbolic link"), "{path}: {error}");
    }

    // the rule file itself
    tree.link("../../outside/secret.txt", "sigs/a/direct.yar");
    let error = refused(tree.outcome("direct.yar"));
    assert!(
        error.contains("the rule file") && error.contains("symbolic link"),
        "{error}"
    );
    tree.link("../../outside/ok.yar", "sigs/a/valid.yar");
    assert!(refused(tree.outcome("valid.yar")).contains("symbolic link"));

    // a namespace that is a link to a directory outside: its files are listed and none is read
    tree.link("../outside", "sigs/linked_namespace");
    let loaded = load_dir(&tree.path("sigs"), &LoadOptions::default()).expect("loads");
    let linked: Vec<_> = loaded
        .files
        .iter()
        .filter(|file| file.namespace == "linked_namespace")
        .collect();
    assert_eq!(linked.len(), 1, "ok.yar is listed");
    assert!(matches!(
        &linked[0].outcome,
        FileOutcome::LeftOut { error } if error.contains("symbolic link") && !error.contains(SECRET)
    ));
    assert!(loaded.rules().all(|rule| rule.name != "outside_rule"));

    // the hash of the sources reads no link either: it is the same whatever the link points to
    let before = crate::ruleset::build(&tree.path("sigs"), &LoadOptions::default())
        .expect("builds")
        .manifest
        .sources_sha256;
    std::fs::write(tree.path("outside/secret.txt"), "something else\n").expect("writes");
    let after = crate::ruleset::build(&tree.path("sigs"), &LoadOptions::default())
        .expect("builds")
        .manifest
        .sources_sha256;
    assert_eq!(before, after);
}

/// What isn't a regular file, or a plain path, is refused, and a missing file says only that.
#[test]
fn only_a_regular_file_by_a_plain_path_is_included() {
    let tree = Tree::new();
    std::fs::create_dir_all(tree.path("sigs/a/directory")).expect("a directory");
    for (path, reason) in [
        ("directory", "isn't a regular file"),
        // the signature directory itself, and the namespace's
        ("..", "isn't a regular file"),
        (".", "isn't a regular file"),
        ("missing.inc", "no such file"),
        ("", "isn't plain text"),
        ("a\\\\b.inc", "isn't plain text"),
        ("..\\\\..\\\\outside\\\\secret.txt", "isn't plain text"),
        (
            "\\x2e\\x2e/\\x2e\\x2e/outside/secret.txt",
            "isn't plain text",
        ),
    ] {
        let error = refused(tree.probe(&format!(
            "include \"{path}\"\nrule r {{ condition: true }}\n"
        )));
        assert!(error.contains(reason), "{path:?}: {error}");
    }
}

/// yara-x itself opens nothing: a compiler as the loader, the export and the tests make it refuses
/// an include it is handed, so a statement `resolve` didn't take is an error and never a read.
#[test]
fn the_compiler_opens_no_file() {
    let tree = Tree::new();
    let secret = tree.path("outside/secret.txt");
    for source in [
        "include \"/etc/passwd\"".to_owned(),
        format!("include \"{}\"", secret.display()),
        format!("include \"\"\"{}\"\"\"", secret.display()),
    ] {
        let mut compiler = new_compiler();
        let error = compiler
            .add_source(source.as_bytes())
            .expect_err("an include is refused")
            .to_string();
        assert!(
            !error.contains(SECRET) && !error.contains("root:"),
            "{error}"
        );
    }
    let mut compiler = new_compiler();
    let error = compiler
        .add_source("include \"/etc/passwd\"".as_bytes())
        .expect_err("refused")
        .to_string();
    assert!(error.contains("include statements not allowed"), "{error}");

    // what `resolve` leaves for yara-x: a path in a triple-quoted string, and an include inside a rule
    for source in [
        format!(
            "include \"\"\"{}\"\"\"\nrule r {{ condition: true }}\n",
            secret.display()
        ),
        format!(
            "rule r {{ condition: true\ninclude \"{}\"\n}}\n",
            secret.display()
        ),
    ] {
        let resolved = tree.resolve(&source).expect("nothing to resolve");
        assert_eq!(resolved.source, source.as_bytes());
        refused(tree.probe(&source));
    }

    // the parser alone, as `crate::source` uses it, reads no file: the rule is listed and that is all
    let rules = crate::source::rules(
        format!(
            "include \"{}\"\nrule own {{ condition: true }}\n",
            secret.display()
        )
        .as_bytes(),
    );
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "own");
}

/// An included file is held to the guard's bounds before yara-x's parser reads it, and so is the
/// whole text; includes nest and number only so far, and a circle is refused.
#[test]
fn an_included_file_is_held_to_the_same_bounds() {
    let tree = Tree::new();
    let deep = format!(
        "rule deep {{ condition: {}true{} }}",
        "(".repeat(5000),
        ")".repeat(5000)
    );
    tree.write("sigs/a/good.inc", "rule g { condition: true }");
    tree.write("sigs/a/deep.inc", &deep);
    tree.write("sigs/a/chain.inc", "include \"deep.inc\"");
    tree.write(
        "sigs/a/self.inc",
        "include \"self.inc\"\nrule s { condition: true }",
    );
    tree.write("sigs/a/loop1.inc", "include \"loop2.inc\"");
    tree.write("sigs/a/loop2.inc", "include \"loop1.inc\"");
    tree.write("sigs/a/probe.yar", "include \"probe.yar\"");

    assert!(tree.resolve("include \"good.inc\"").is_ok());
    for including in [
        "include \"deep.inc\"",
        "include \"chain.inc\"",
        "include\n/* x */ \"./deep.inc\"",
    ] {
        let refusal = tree.resolve(including).expect_err("refused").to_string();
        assert!(refusal.contains("nests brackets"), "{refusal}");
    }
    for including in [
        "include \"self.inc\"",
        "include \"loop1.inc\"",
        "include \"probe.yar\"",
    ] {
        let refusal = tree.resolve(including).expect_err("refused").to_string();
        assert!(refusal.contains("circular"), "{refusal}");
    }

    // a chain deeper than the limit, more files than the limit, and more bytes
    for i in 0..=MAX_INCLUDE_DEPTH {
        tree.write(
            &format!("sigs/a/c{i}.inc"),
            &format!("include \"c{}.inc\"", i + 1),
        );
    }
    tree.write(
        &format!("sigs/a/c{}.inc", MAX_INCLUDE_DEPTH + 1),
        "rule end { condition: true }",
    );
    // c2 to the end is eight includes, one inside the other; c1 is nine
    assert_eq!(tree.resolve("include \"c1.inc\""), Err(Refusal::Depth));
    assert!(tree.resolve("include \"c2.inc\"").is_ok());
    let mut many = String::new();
    for i in 0..=MAX_INCLUDED_FILES {
        tree.write(
            &format!("sigs/a/m{i}.inc"),
            &format!("rule m{i} {{ condition: true }}"),
        );
        many.push_str(&format!("include \"m{i}.inc\"\n"));
    }
    assert_eq!(tree.resolve(&many), Err(Refusal::Count));
    let comment = format!("// {}\n", "x".repeat(1 << 20));
    tree.write("sigs/a/big.inc", &comment.repeat(3));
    assert!(
        tree.resolve("include \"big.inc\"\ninclude \"big.inc\"")
            .is_ok()
    );
    assert_eq!(
        tree.resolve("include \"big.inc\"\ninclude \"big.inc\"\ninclude \"big.inc\""),
        Err(Refusal::Size)
    );
}

/// An included file has to be whole: one that leaves a comment or a rule open would otherwise take
/// what follows it. The reason names its line and none of its text.
#[test]
fn an_included_file_parses_on_its_own() {
    let tree = Tree::new();
    tree.write(
        "sigs/a/open_comment.inc",
        "rule c { condition: true }\n/* never closed\n",
    );
    tree.write("sigs/a/open_rule.inc", "rule o {\n  condition:\n    true\n");
    tree.write(
        "sigs/a/not_yara.inc",
        &format!("{SECRET} is in the repository, and still not quoted\n"),
    );
    tree.write(
        "sigs/a/latin1.inc",
        "rule l { condition: true } // caf\u{e9}",
    );
    std::fs::write(
        tree.path("sigs/a/bytes.inc"),
        b"rule caf\xe9 { condition: true }",
    )
    .expect("writes");
    tree.write(
        "sigs/a/comment_end.inc",
        "rule e { condition: true } // no newline",
    );
    for (path, reason) in [
        ("open_comment.inc", "doesn't parse on its own"),
        ("open_rule.inc", "doesn't parse on its own"),
        ("not_yara.inc", "its line 1"),
        ("bytes.inc", "isn't UTF-8"),
    ] {
        let error = refused(tree.probe(&format!(
            "include \"{path}\"\nrule after {{ condition: true }}\n"
        )));
        assert!(error.contains(reason), "{path}: {error}");
    }
    // a last line that is a comment doesn't take the next line with it
    assert_eq!(
        tree.probe("include \"comment_end.inc\" rule after { condition: e }\n"),
        Ok(vec!["e".to_owned(), "after".to_owned()])
    );
    assert_eq!(
        tree.probe("include \"latin1.inc\"\nrule after { condition: l }\n"),
        Ok(vec!["l".to_owned(), "after".to_owned()])
    );
}

/// An error in a file with includes says which lines are whose, since yara-x counts the lines of
/// the text with the included files in place.
#[test]
fn an_error_says_which_lines_are_an_included_file_s() {
    let tree = Tree::new();
    tree.write(
        "sigs/a/three.inc",
        "rule t1 { condition: true }\nrule t2 { condition: true }\nrule t3 { condition: true }\n",
    );
    let source =
        "rule before { condition: true }\ninclude \"three.inc\"\nrule broken { condition: nope }\n";
    let resolved = tree.resolve(source).expect("resolves");
    assert_eq!(
        resolved.inlined,
        [Inlined {
            include: "three.inc".to_owned(),
            first_line: 2,
            last_line: 4,
        }]
    );
    assert_eq!(
        String::from_utf8_lossy(&resolved.source),
        "rule before { condition: true }\nrule t1 { condition: true }\nrule t2 { condition: true }\n\
         rule t3 { condition: true }\n\nrule broken { condition: nope }\n"
    );
    let error = tree.probe(source).expect_err("left out");
    assert!(error.contains("a/probe.yar:6:"), "{error}");
    assert!(error.contains("lines 2 to 4 are \"three.inc\""), "{error}");
    // a file with no include has no note
    let error = tree
        .probe("rule broken { condition: nope }\n")
        .expect_err("left out");
    assert!(!error.contains("note:"), "{error}");
}

/// The boundary is the directory that holds the namespace's, however the namespace is named.
#[test]
fn the_boundary_is_the_signature_directory() {
    assert_eq!(
        Boundary::of_namespace(Path::new("/x/sigs/a")).root(),
        Path::new("/x/sigs")
    );
    assert_eq!(
        Boundary::of_namespace(Path::new("sigs/a")).root(),
        Path::new("sigs")
    );
    assert_eq!(
        Boundary::of_namespace(Path::new("a")).root(),
        Path::new(".")
    );
    assert_eq!(
        Boundary::of_namespace(Path::new("/")).root(),
        Path::new("/")
    );
    // a rule file that isn't inside its namespace's signature directory isn't read
    let tree = Tree::new();
    assert_eq!(
        tree.boundary().read_rule_file(&tree.path("outside/ok.yar")),
        Err(Refusal::File(Why::Outside))
    );
    assert_eq!(
        tree.boundary()
            .read_rule_file(&tree.path("sigs/a/../../outside/ok.yar")),
        Err(Refusal::File(Why::Outside))
    );
}
