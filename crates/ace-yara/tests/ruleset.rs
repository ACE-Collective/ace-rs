//! PLAN.md 1.6: a serialized ruleset is keyed by its hash, and two builds of the same commit
//! give the same key.
//!
//! yara-x's serialization turned out deterministic, so the key is the sha256 of the bytes.
//! The builds compared here run in two processes and from two checkouts in different
//! directories, so neither per-process hash seeds nor paths can hide in the bytes.

use crate::common;

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ace_yara::ruleset::{
    BuiltIn, Manifest, Owned, build, build_commit, build_commit_owning, build_commit_with,
    built_ins_sha256, resolve_commit,
};
use ace_yara::{LoadOptions, Ruleset, ScanRequest, Scanner};
use common::fixture;

/// Set to a signature directory to make `print_build_key` print that directory's build.
const KEY_DIR_VAR: &str = "ACE_RS_YARA_TEST_BUILD_DIR";

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=ace-rs test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .output()
        .expect("git runs");
    assert!(output.status.success(), "git {args:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

/// A git repository holding the fixture rules under `signatures/`, and its commit.
fn repository(root: &Path) -> String {
    copy_dir(&fixture("ruleset/signatures"), &root.join("signatures"));
    git(root, &["init", "-q"]);
    git(root, &["add", "."]);
    git(root, &["commit", "-q", "-m", "rules"]);
    git(root, &["rev-parse", "HEAD"])
}

/// The manifest of a build of `dir` in a new process: this test binary, running only
/// `print_build_key`.
fn manifest_in_another_process(dir: &Path) -> Manifest {
    // libtest names a test by its path in the test program: this module's, less the crate's name
    let (_, module) = module_path!()
        .split_once("::")
        .expect("a module of tests/main.rs");
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("{module}::print_build_key"),
            "--ignored",
            "--nocapture",
        ])
        .env(KEY_DIR_VAR, dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let line = stdout
        .lines()
        .find_map(|l| l.strip_prefix("MANIFEST "))
        .unwrap_or_else(|| panic!("no manifest in {stdout}"));
    serde_json::from_str(line).unwrap()
}

#[test]
#[ignore = "run by manifest_in_another_process"]
fn print_build_key() {
    let dir = std::env::var(KEY_DIR_VAR).expect("the directory to build");
    let built = build(Path::new(&dir), &LoadOptions::default()).unwrap();
    println!(
        "MANIFEST {}",
        serde_json::to_string(&built.manifest).unwrap()
    );
}

#[test]
fn two_builds_of_the_same_commit_give_the_same_key() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first");
    let commit = repository(&first);

    let here = build(&first.join("signatures"), &LoadOptions::default()).unwrap();
    assert_eq!(here.manifest.commit.as_deref(), Some(commit.as_str()));
    assert_eq!(here.manifest.key.len(), 64);

    // Again in this process.
    let again = build(&first.join("signatures"), &LoadOptions::default()).unwrap();
    assert_eq!(again.manifest.key, here.manifest.key);
    assert_eq!(again.bytes, here.bytes);

    // In another process, from a clone of the commit in another directory.
    let second = temp.path().join("elsewhere/second");
    std::fs::create_dir_all(second.parent().unwrap()).unwrap();
    git(
        temp.path(),
        &[
            "clone",
            "-q",
            first.to_str().unwrap(),
            second.to_str().unwrap(),
        ],
    );
    let there = manifest_in_another_process(&second.join("signatures"));
    assert_eq!(there.commit.as_deref(), Some(commit.as_str()));
    assert_eq!(there.key, here.manifest.key);
    assert_eq!(there, here.manifest);
}

#[test]
fn the_manifest_lists_the_files_and_rules_included_and_the_files_left_out() {
    let built = build(&fixture("ruleset/signatures"), &LoadOptions::default()).unwrap();
    let manifest = &built.manifest;

    assert_eq!(manifest.yara_x_version, yara_x::VERSION);
    let included: Vec<_> = manifest
        .files
        .iter()
        .map(|f| (f.namespace.as_str(), f.path.as_str(), f.rules.clone()))
        .collect();
    assert_eq!(
        included,
        [
            ("one", "one/a.yar", vec!["one_a".to_string()]),
            ("two", "two/b.yar", vec!["two_b".into(), "two_c".into()]),
        ]
    );
    assert_eq!(manifest.left_out.len(), 1);
    assert_eq!(manifest.left_out[0].path, "one/broken.yar");
    assert!(manifest.left_out[0].error.contains("not_defined"));
}

/// PLAN.md 5.6's `yara_qa` router lists the rules in QA mode from the manifest, with their uuid,
/// `enabled` and tags, whether or not they're enabled. Rules not in QA mode aren't listed.
#[test]
fn the_manifest_lists_the_rules_in_qa_mode() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    std::fs::create_dir_all(dir.join("ns")).unwrap();
    std::fs::write(
        dir.join("ns/qa.yar"),
        r#"
rule normal { meta: uuid = "11111111-1111-1111-1111-111111111111" condition: false }
rule in_qa : one two {
    meta:
        uuid = " 22222222-2222-2222-2222-222222222222 "
        modifiers = "no_alert, qa"
        description = "<script>alert(1)</script>"
    condition: false
}
rule qa_off { meta: modifiers = "qa" enabled = "false" condition: false }
rule qa_blank_uuid { meta: modifiers = "qa" uuid = "  " condition: false }
"#,
    )
    .unwrap();
    let built = build(dir, &LoadOptions::default()).unwrap();
    let qa: Vec<_> = built
        .manifest
        .qa_rules
        .iter()
        .map(|r| {
            (
                r.namespace.as_str(),
                r.path.as_str(),
                r.name.as_str(),
                r.uuid.as_deref(),
                r.enabled,
                r.tags.clone(),
            )
        })
        .collect();
    assert_eq!(
        qa,
        [
            (
                "ns",
                "ns/qa.yar",
                "in_qa",
                Some("22222222-2222-2222-2222-222222222222"),
                true,
                vec!["one".to_string(), "two".into()]
            ),
            ("ns", "ns/qa.yar", "qa_off", None, false, vec![]),
            ("ns", "ns/qa.yar", "qa_blank_uuid", None, true, vec![]),
        ]
    );
    // a manifest written before the field existed reads it as empty
    let mut old = serde_json::to_value(&built.manifest).unwrap();
    old.as_object_mut().unwrap().remove("qa_rules");
    let old: Manifest = serde_json::from_value(old).unwrap();
    assert!(old.qa_rules.is_empty());
}

/// What SVS reads of each rule with a `uuid` meta (PLAN.md 7.10 batch 5): its name, the hash of its own
/// text, its tags with its `mitre_attack` meta's techniques, and whether they count.
#[test]
fn the_manifest_lists_each_rule_with_a_uuid_as_a_signature() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    std::fs::create_dir_all(dir.join("ns")).unwrap();
    let plain = "rule plain : zeta alpha {\n    meta:\n        uuid = \" 11111111-1111-1111-1111-111111111111 \"\n        mitre_attack = \"T1059.001, T1105 ,\"\n    condition: false\n}\n";
    let source = format!(
        "{plain}rule in_qa {{ meta: uuid = \"22222222-2222-2222-2222-222222222222\" modifiers = \"qa\" condition: false }}\n\
         rule off {{ meta: uuid = \"33333333-3333-3333-3333-333333333333\" enabled = \"false\" condition: false }}\n\
         rule nameless {{ condition: false }}\n\
         rule again {{ meta: uuid = \"11111111-1111-1111-1111-111111111111\" condition: false }}\n"
    );
    std::fs::write(dir.join("ns/rules.yar"), &source).unwrap();
    let built = build(dir, &LoadOptions::default()).unwrap();
    let signatures: Vec<_> = built
        .manifest
        .signatures
        .iter()
        .map(|s| (s.uuid.as_str(), s.name.as_str(), s.counts, s.tags.clone()))
        .collect();
    assert_eq!(
        signatures,
        [
            (
                "11111111-1111-1111-1111-111111111111",
                "plain",
                true,
                vec![
                    "alpha".to_string(),
                    "mitre:T1059.001".into(),
                    "mitre:T1105".into(),
                    "zeta".into()
                ]
            ),
            (
                "22222222-2222-2222-2222-222222222222",
                "in_qa",
                false,
                vec![]
            ),
            ("33333333-3333-3333-3333-333333333333", "off", false, vec![]),
        ],
        "a rule without a uuid isn't one, and a uuid's first rule is its signature"
    );
    // the hash is the sha256 of the rule's own text, as ace3's inventory computes it
    use sha2::{Digest, Sha256};
    let expected: String = Sha256::digest(plain.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(built.manifest.signatures[0].content_hash, expected);
    let mut old = serde_json::to_value(&built.manifest).unwrap();
    old.as_object_mut().unwrap().remove("signatures");
    let old: Manifest = serde_json::from_value(old).unwrap();
    assert!(old.signatures.is_empty());
}

#[test]
fn a_directory_outside_git_is_known_by_the_hash_of_its_sources() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    repository(&repo);
    let in_git = build(&repo.join("signatures"), &LoadOptions::default()).unwrap();

    // The same files outside git: no commit, the same sources hash and the same key.
    let plain = temp.path().join("plain");
    copy_dir(&fixture("ruleset/signatures"), &plain);
    let outside = build(&plain, &LoadOptions::default()).unwrap();
    assert_eq!(outside.manifest.commit, None);
    assert_eq!(
        outside.manifest.sources_sha256,
        in_git.manifest.sources_sha256
    );
    assert_eq!(outside.manifest.key, in_git.manifest.key);

    // A changed rule changes both.
    std::fs::write(plain.join("two/b.yar"), "rule two_b { condition: false }\n").unwrap();
    let changed = build(&plain, &LoadOptions::default()).unwrap();
    assert_ne!(
        changed.manifest.sources_sha256,
        outside.manifest.sources_sha256
    );
    assert_ne!(changed.manifest.key, outside.manifest.key);

    // So does a change to a file that is left out, which the key alone wouldn't show.
    std::fs::write(plain.join("one/broken.yar"), "rule one_broken {").unwrap();
    let broken_changed = build(&plain, &LoadOptions::default()).unwrap();
    assert_ne!(
        broken_changed.manifest.sources_sha256,
        changed.manifest.sources_sha256
    );
    assert_eq!(broken_changed.manifest.key, changed.manifest.key);
}

#[test]
fn a_checkout_with_uncommitted_changes_records_no_commit() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    repository(&repo);
    std::fs::write(
        repo.join("signatures/two/new.yar"),
        "rule untracked { condition: true }\n",
    )
    .unwrap();
    let built = build(&repo.join("signatures"), &LoadOptions::default()).unwrap();
    assert_eq!(built.manifest.commit, None);
}

#[test]
fn a_ruleset_loaded_from_its_bytes_scans_like_the_one_built() {
    let built = build(&fixture("ruleset/signatures"), &LoadOptions::default()).unwrap();
    let loaded = Ruleset::from_bytes(&built.bytes, &LoadOptions::default()).unwrap();

    let tags = vec!["type=email.attachment".to_string()];
    let request = ScanRequest {
        data: b"MZ\x90\x00\x01\x02PE needle haySTACKstack",
        path: "alert/sample.bin",
        mime_type: "application/octet-stream",
        meta_tags: &tags,
        timeout: Some(Duration::from_secs(5)),
    };
    let from_build = Scanner::new(&built.ruleset).scan(&request).unwrap();
    let from_bytes = Scanner::new(&loaded).scan(&request).unwrap();
    assert_eq!(from_bytes, from_build);
    assert!(!from_build.matches.is_empty());

    // The filters were compiled again: without the tag, one_a is dropped.
    let untagged = ScanRequest {
        meta_tags: &[],
        ..request
    };
    let outcome = Scanner::new(&loaded).scan(&untagged).unwrap();
    assert!(outcome.dropped.iter().any(|m| m.rule == "one_a"));
}

/// A built-in rule file joins the commit's export as its own namespace, replacing a file of the same
/// name there, and the repository itself never changes (PLAN.md 7.10 batch 6: SVS's marker rule, ace3's
/// `install_marker_rule`).
#[test]
fn built_ins_join_the_commit_s_export() {
    const OURS: BuiltIn = BuiltIn {
        namespace: "ace_own",
        file: "ace_own.yar",
        source: "rule ace_own_rule { strings: $a = \"OWN\" condition: $a }\n",
    };
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let commit = repository(&repo);
    let dir = Path::new("signatures");
    let options = LoadOptions::default();
    let plain = build_commit(&repo, &commit, dir, &options).expect("builds");
    let with = build_commit_with(&repo, &commit, dir, &options, &[OURS]).expect("builds");
    let own: Vec<_> = with
        .manifest
        .files
        .iter()
        .filter(|f| f.namespace == "ace_own")
        .collect();
    assert_eq!(own.len(), 1);
    assert_eq!(own[0].path, "ace_own/ace_own.yar");
    assert_eq!(own[0].rules, ["ace_own_rule"]);
    assert_eq!(with.manifest.files.len(), plain.manifest.files.len() + 1);
    assert_ne!(with.manifest.key, plain.manifest.key);
    assert_ne!(with.manifest.sources_sha256, plain.manifest.sources_sha256);
    // the same built-ins give the same ruleset, and nothing was written into the repository
    let again = build_commit_with(&repo, &commit, dir, &options, &[OURS]).expect("builds");
    assert_eq!(again.manifest.key, with.manifest.key);
    assert!(!repo.join("signatures/ace_own").exists());
    assert!(git(&repo, &["status", "--porcelain"]).trim().is_empty());

    // the repository's own file of that name gives way to the built-in, and so does a file where the
    // namespace's directory should be (ace3 logs that and scans without the rule)
    std::fs::create_dir_all(repo.join("signatures/ace_own")).unwrap();
    std::fs::write(
        repo.join("signatures/ace_own/ace_own.yar"),
        "rule theirs { condition: false }\n",
    )
    .unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "their own"]);
    let theirs = resolve_commit(&repo, "HEAD").unwrap();
    let replaced = build_commit_with(&repo, &theirs, dir, &options, &[OURS]).expect("builds");
    assert_eq!(replaced.manifest.key, with.manifest.key);
    git(&repo, &["rm", "-r", "-q", "signatures/ace_own"]);
    std::fs::write(repo.join("signatures/ace_own"), "a file, not a directory").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "a file in the way"]);
    let blocked = resolve_commit(&repo, "HEAD").unwrap();
    let cleared = build_commit_with(&repo, &blocked, dir, &options, &[OURS]).expect("builds");
    assert_eq!(cleared.manifest.key, with.manifest.key);

    // which built-ins a ruleset holds is named by a hash that follows their content
    let changed = BuiltIn {
        source: "rule ace_own_rule { condition: false }\n",
        ..OURS
    };
    assert_eq!(built_ins_sha256(&[OURS]), built_ins_sha256(&[OURS]));
    assert_ne!(built_ins_sha256(&[OURS]), built_ins_sha256(&[changed]));
    assert_ne!(built_ins_sha256(&[OURS]), built_ins_sha256(&[]));
}

/// A namespace the builder owns holds its files and nothing of the commit's: the export of the
/// observables enabled for detection (PLAN.md 7.16), where ace3 removes the files it no longer exports.
#[test]
fn an_owned_namespace_replaces_the_commit_s() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    repository(&repo);
    let dir = Path::new("signatures");
    let options = LoadOptions::default();
    // the repository has rules of its own under the export's name, an index among them
    std::fs::create_dir_all(repo.join("signatures/observable_export")).unwrap();
    std::fs::write(
        repo.join("signatures/observable_export/theirs.yar"),
        // "url" and "planted" in hex
        "rule obsd_index { meta: e7 = \"75726c:706c616e746564\" condition: false }\n\
         rule theirs { strings: $obsd_7 = \"PLANTED\" condition: $obsd_7 }\n",
    )
    .unwrap();
    git(&repo, &["add", "-A"]);
    git(
        &repo,
        &["commit", "-q", "-m", "rules under the export's name"],
    );
    let commit = resolve_commit(&repo, "HEAD").unwrap();
    let kept = build_commit(&repo, &commit, dir, &options).expect("builds");
    assert_eq!(kept.ruleset.detection(7), Some(("url", "planted")));

    let ours = Owned {
        namespace: "observable_export".to_owned(),
        files: vec![(
            "fqdn.yar".to_owned(),
            "rule detect_fqdn { strings: $obsd_1 = \"evil.example\" condition: any of them }\n"
                .to_owned(),
        )],
    };
    let owned = build_commit_owning(
        &repo,
        &commit,
        dir,
        &options,
        &[],
        std::slice::from_ref(&ours),
    )
    .expect("builds");
    let files: Vec<&str> = owned
        .manifest
        .files
        .iter()
        .filter(|f| f.namespace == "observable_export")
        .map(|f| f.path.as_str())
        .collect();
    assert_eq!(files, ["observable_export/fqdn.yar"]);
    assert_eq!(owned.ruleset.detection(7), None);
    assert!(git(&repo, &["status", "--porcelain"]).trim().is_empty());

    // with no files the namespace is gone
    let empty = Owned {
        namespace: "observable_export".to_owned(),
        files: Vec::new(),
    };
    let none = build_commit_owning(&repo, &commit, dir, &options, &[], &[empty]).expect("builds");
    assert!(
        none.manifest
            .files
            .iter()
            .all(|f| f.namespace != "observable_export")
    );

    // a name that would leave the namespace is refused
    for (namespace, file) in [
        ("../out", "a.yar"),
        ("observable_export", "../a.yar"),
        ("", "a.yar"),
    ] {
        let bad = Owned {
            namespace: namespace.to_owned(),
            files: vec![(file.to_owned(), "rule x { condition: true }".to_owned())],
        };
        assert!(build_commit_owning(&repo, &commit, dir, &options, &[], &[bad]).is_err());
    }
}

/// Owns every file under `path` by `uid`.
fn chown_all(path: &Path, uid: u32) {
    std::os::unix::fs::lchown(path, Some(uid), Some(uid)).unwrap();
    if path.is_dir() && !path.is_symlink() {
        for entry in std::fs::read_dir(path).unwrap() {
            chown_all(&entry.unwrap().path(), uid);
        }
    }
}

/// A checkout owned by another user, as one bind-mounted into the core's container is, still
/// builds; git refuses such a repository unless it is a safe directory. Only root can give the
/// checkout away, so the test is skipped elsewhere.
#[test]
fn a_checkout_another_user_owns_builds() {
    use std::os::unix::fs::MetadataExt;
    let temp = tempfile::tempdir().unwrap();
    // the new directory is owned by this process's user
    if std::fs::metadata(temp.path()).unwrap().uid() != 0 {
        eprintln!("skipped: only root can give the checkout to another user");
        return;
    }
    let repo = temp.path().join("repo");
    let commit = repository(&repo);
    chown_all(&repo, 10_002);
    let refused = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("dubious ownership"),
        "plain git refuses the checkout: {refused:?}"
    );
    assert_eq!(resolve_commit(&repo, "HEAD").unwrap(), commit);
    let built = build_commit(
        &repo,
        &commit,
        Path::new("signatures"),
        &LoadOptions::default(),
    )
    .expect("builds");
    assert_eq!(built.manifest.commit.as_deref(), Some(commit.as_str()));
}
