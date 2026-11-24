#!/usr/bin/env python3
"""Collect everything /ace-review needs about one repo's change into a bundle directory.

    prepare.py --list
    prepare.py [--repo PATH] [--base REF | --range A..B] [--full] [--coverage]
               [--exec PREFIX] [--state-dir DIR]
    prepare.py --check [--repo PATH] [--base REF | --range A..B]

--check is for the author, before asking for a review: it prints what the mechanical
checks below find in the lines the change adds, each with the fix it expects, writes
no bundle, and exits 1 when it finds anything.

The repo is ace-rs, or a site's own Cargo workspace that depends on ace-rs's crates by
git tag. Plain git and the standard library only: this runs on the host with python3,
not in the dev container. Every review of a branch is a round, in its own bundle
directory <state-dir>/<repo>-<branch>/round-<N>/ (state-dir defaults to local/ace-review
in the ace-rs checkout this script is in). A round counts as finished once findings.py
has written its summary.json; an unfinished one is redone in place. The bundle gets:

    target.json        repo, kind, base, merge-base, head, round, delta, rule changes and
                       the test scope; printed on stdout as well
    diff.patch         the full diff from the merge-base, including uncommitted and
                       untracked work when reviewing the checked-out branch
    stat.txt           git diff --stat
    files.txt          changed files, one per line, "<status>\t<path relative to repo>"
    log.txt            commit subjects and bodies in the range
    checks.sh          the checks to run, in the repo's dev container: fmt, clippy, the
                       tests of the packages in scope, the doctests, the sqlx check and the
                       layering check when the change can affect them, and with --coverage
                       an instrumented run of the same tests; each step's output and
                       "exit[<step>]=<code>" go to stdout (run it as sh checks.sh > checks.txt)
    rules/AGENTS.md    ace-rs's AGENTS.md from the base, which the change is judged by (for a
                       site workspace, from the ace-rs tag it pins where this checkout has it;
                       rules/repo-AGENTS.md is then the site's own, from its base)
    rule-changes.patch what the change does to the AGENTS.md rule sections or to the skill
                       itself, when it does anything
    related-docs.txt   lines of the repo's Markdown, at the base, that name a file the change
                       touches, when any do
    leads.json         added lines that match a mechanical check, functions the change adds
                       that repeat another function's body, and doc lines that name a path,
                       item, variable or YAML key the change removes
    previous.json      round 2 on: every finding of earlier rounds and its status, one of
                       open (the lead's act on), fixed, dismissed (by the user's answer) or
                       seen (consider, noted and pre-existing findings, never rechecked)
    delta.patch        round 2 on, when the merge-base hasn't moved: what changed since the
                       last finished round (delta-files.txt lists the files)
"""

import argparse
import codecs
import difflib
import fnmatch
import functools
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = ".agents/skills/ace-review"
# the file a repo's rules are in: AGENTS.md, or CLAUDE.md in a repo that has no AGENTS.md. Where
# both exist CLAUDE.md is the one-line @AGENTS.md import.
RULES_FILES = ("AGENTS.md", "CLAUDE.md")
# the AGENTS.md sections that state rules rather than facts about the code
RULE_SECTIONS = ("## Engineering values", "## Conventions")
DIFF_FLAGS = ["--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/", "-M"]
DISMISSING_ANSWERS = {"wrong", "intentional", "didn't matter"}
STALE_HITS_PER_REF = 10
RELATED_DOC_HITS = 5
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
# a change here can change how every crate builds, so the whole workspace is tested
WORKSPACE_FILES = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rust-toolchain", "sqlx.toml"}
WORKSPACE_DIRS = (".cargo/", ".config/", "vendor/")
# past this share of the workspace's packages, -p lists cost more to read than --workspace saves
WORKSPACE_SHARE = 0.6
MIGRATION = re.compile(r"(^|/)migrations/(\d+)_[^/]+\.sql$")
COVERAGE_MIN_FREE_GB = 35
# a shorter function is a copy by coincidence more often than by pasting
COPY_MIN_STATEMENTS = 3
COPY_ANCHOR_MIN = 25
# Markdown that records history (a measurement's command as it was run) or is data, not instructions
DOC_SKIP = ("tests/", "samples/", "vendor/", "docs/measurements/", "tools/ace3/dumps/", "tools/ace3/trees/")
# crates whose prints are a command's output, not a log line
CLI_CRATES = {"ace-app"}

# what --check tells the author to do about each kind of lead
CHECK_FIXES = {
    "unbounded-wait": "bound it with tokio::time::timeout, or say in a comment on the line above what bounds it",
    "no-timeout": "give the connection a timeout (ace-sdk's HttpClient has one), or bound the call with tokio::time::timeout",
    "app-clock": "compare with the database's now() in the SQL instead of binding the application's clock",
    "edited-migration": "leave the applied migration as it was and put the change in a new numbered migration: sqlx refuses a migration whose checksum changed",
    "migration-order": "number the new migration after the highest one on the base branch, with no number used twice",
    "blocking-migration": "keep it short on a live table: SET LOCAL lock_timeout so it fails rather than holding writes, batch a data change, or build the index CONCURRENTLY in a migration of its own that starts with -- no-transaction",
    "print-in-library": "log it with tracing, with its identifiers as fields; a print before tracing is set up says so in a comment",
    "dbg": "remove the dbg!",
    "error-without-chain": "log an anyhow error with {e:#}, which prints its whole chain; {e} prints only the outermost message",
    "error-hides-source": "name the source in the message ({0}, {source}) or use #[error(transparent)], so a log of {e} keeps the chain",
    "dropped-error": "handle or log the error, or say in a comment why dropping it is right",
    "sleep-in-test": "wait for the state the test needs (a row, a count, a log record) with a deadline, not for time to pass",
    "wall-clock-assert": "assert on the state, not on how long it took; a bound only as a generous hang guard, with a comment saying so",
    "ignore-without-reason": "give the reason: #[ignore = \"why\"]",
    "undeclared-test-file": "declare it in tests/main.rs (mod <name>;), or it is never built",
    "offset-paging": "page by keyset along an index, with a bounded page size (ace-service's detection_points.rs and page_limit)",
    "query-in-loop": "one query for the whole set: bind an array with = ANY($1), or join",
    "todo": "write the code, or return an error saying it isn't supported",
    "sql-format": "bind values as $n parameters; build in only identifiers from a fixed list, with a comment saying so",
    "shell-command": "run the program directly with an argument list, not through a shell",
    "sqlx-data": "run `cargo sqlx migrate run && cargo sqlx prepare --workspace` in the dev container and commit .sqlx/",
    "copied-function": "call or move the existing function instead of copying it",
    "stale-reference": "update the doc line that still names what the change removes",
}


def git(repo: str, *args: str, check: bool = True) -> str:
    result = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, errors="replace")
    if check and result.returncode != 0:
        sys.exit(f"git {' '.join(args)} failed in {repo}: {result.stderr.strip()}")
    return result.stdout


def show(repo: str, rev: str, path: str) -> str | None:
    """A file's content at a revision, or None where it doesn't exist there."""
    result = subprocess.run(["git", "-C", repo, "show", f"{rev}:{path}"], capture_output=True, text=True, errors="replace")
    return result.stdout if result.returncode == 0 else None


def read_file(path: str) -> str | None:
    """A file's content on disk, or None where there is no file."""
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as fp:
        return fp.read()


def load_json(path: str, default):
    if not os.path.exists(path):
        return default
    with open(path) as fp:
        return json.load(fp)


def toplevel(path: str) -> str:
    return git(path, "rev-parse", "--show-toplevel").strip()


def ace_rs_checkout() -> str:
    """The ace-rs checkout this script runs from, whose local/ holds the rounds."""
    return toplevel(HERE)


def detect_base(repo: str) -> str | None:
    head = git(repo, "symbolic-ref", "--quiet", "refs/remotes/origin/HEAD", check=False).strip()
    if head:
        return head.removeprefix("refs/remotes/")
    for ref in ("origin/main", "main", "origin/master", "master"):
        if git(repo, "rev-parse", "--verify", "--quiet", ref, check=False).strip():
            return ref
    return None


def list_repos() -> None:
    """The ace-rs checkout and its worktrees, with what each has to review."""
    main = ace_rs_checkout()
    seen = []
    for line in git(main, "worktree", "list", "--porcelain").splitlines():
        if line.startswith("worktree "):
            seen.append(line.removeprefix("worktree "))
    for repo in seen or [main]:
        if not os.path.isdir(repo):
            continue
        base = detect_base(repo)
        branch = git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
        dirty = len(git(repo, "status", "--porcelain").splitlines())
        ahead = git(repo, "rev-list", "--count", f"{base}..HEAD", check=False).strip() if base else "?"
        print(f"{repo}\tbranch={branch}\tbase={base}\tahead={ahead}\tuncommitted={dirty}")
    print("A site's workspace is a repo of its own: pass it with --repo.")


# --- the workspace ----------------------------------------------------------------------


def parse_toml(text: str | None) -> dict:
    try:
        return tomllib.loads(text or "")
    except tomllib.TOMLDecodeError:
        return {}


def dependency_tables(manifest: dict):
    """Every dependency table of a manifest: normal, dev, build, and each target's."""
    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        yield manifest.get(key, {})
    for target in manifest.get("target", {}).values():
        for key in ("dependencies", "dev-dependencies", "build-dependencies"):
            yield target.get(key, {})


def workspace(tree_files: list[str], head_text) -> dict:
    """The workspace's packages: name, directory, whether it has a library, and the workspace
    packages each depends on by path."""
    root = parse_toml(head_text("Cargo.toml"))
    members = root.get("workspace", {}).get("members", [])
    excluded = root.get("workspace", {}).get("exclude", [])
    manifests = [p for p in tree_files if p.endswith("/Cargo.toml") or p == "Cargo.toml"]
    dirs = []
    for path in manifests:
        directory = os.path.dirname(path)
        if any(fnmatch.fnmatch(directory, m) for m in members) and not any(fnmatch.fnmatch(directory, e) for e in excluded):
            dirs.append(directory)
    if not dirs and "package" in root:
        dirs = [""]
    workspace_paths = {name: spec.get("path") for name, spec in root.get("workspace", {}).get("dependencies", {}).items()
                       if isinstance(spec, dict) and spec.get("path")}
    packages = {}
    for directory in dirs:
        manifest = parse_toml(head_text(os.path.join(directory, "Cargo.toml")))
        name = manifest.get("package", {}).get("name")
        if not name:
            continue
        deps = set()
        for table in dependency_tables(manifest):
            for dep, spec in table.items():
                if not isinstance(spec, dict):
                    continue
                real = spec.get("package", dep)
                if spec.get("path"):
                    deps.add(os.path.normpath(os.path.join(directory, spec["path"])))
                elif spec.get("workspace") and workspace_paths.get(real):
                    deps.add(os.path.normpath(workspace_paths[real]))
        has_lib = "lib" in manifest or os.path.join(directory, "src/lib.rs").lstrip("/") in tree_files
        packages[directory] = {"name": name, "dir": directory, "lib": has_lib, "deps": deps}
    for package in packages.values():
        package["deps"] = {packages[d]["name"] for d in package["deps"] if d in packages}
    return {p["name"]: p for p in packages.values()}


def owner(path: str, packages: dict) -> str | None:
    """The package whose directory holds path, the deepest one."""
    best = None
    for package in packages.values():
        directory = package["dir"]
        if (not directory or path.startswith(directory + "/")) and (best is None or len(directory) > len(packages[best]["dir"])):
            best = package["name"]
    return best


def test_scope(changed: list[tuple[str, str, str]], packages: dict) -> dict:
    """Which packages' tests the change needs: the ones it changes, and every package that depends
    on one whose code it changes (a change to a package's tests/, benches/ or examples/ reaches no
    other package), or the whole workspace when it changes how everything builds."""
    paths = {p for _, old, new in changed for p in (old, new)}
    shared = sorted(p for p in paths if p in WORKSPACE_FILES or p.startswith(WORKSPACE_DIRS))
    outside = sorted(p for p in paths if owner(p, packages) is None and not p.endswith(".md") and p not in shared)
    if shared:
        return {"workspace": True, "packages": sorted(packages), "changed": [], "outside": outside,
                "reason": f"it changes {', '.join(shared[:3])}, which every package builds with"}
    direct, reaching = set(), set()
    for path in paths:
        if name := owner(path, packages):
            direct.add(name)
            inner = path[len(packages[name]["dir"]):].lstrip("/")
            if not inner.startswith(("tests/", "benches/", "examples/")):
                reaching.add(name)
    if not direct:
        return {"workspace": False, "packages": [], "changed": [], "outside": outside, "reason": "it changes no package"}
    dependents: dict[str, set[str]] = {name: set() for name in packages}
    for package in packages.values():
        for dep in package["deps"]:
            dependents[dep].add(package["name"])
    selected, stack = set(direct), list(reaching)
    while stack:
        for user in dependents.get(stack.pop(), ()):
            if user not in selected:
                selected.add(user)
                stack.append(user)
    changed_list = sorted(direct)
    if len(selected) > len(direct) and len(selected) > WORKSPACE_SHARE * len(packages):
        return {"workspace": True, "packages": sorted(selected), "changed": changed_list, "outside": outside,
                "reason": f"{len(selected)} of the workspace's {len(packages)} packages are the changed ones or depend on them"}
    if len(selected) > len(direct):
        reason = f"the changed packages and the {len(selected) - len(direct)} that depend on them"
    elif reaching:
        reason = "the changed packages; nothing depends on them"
    else:
        reason = "the changed packages; the change is in their tests only"
    return {"workspace": False, "packages": sorted(selected), "changed": changed_list, "outside": outside, "reason": reason}


def coverage_skips(repo: str) -> list[str]:
    """The tests make coverage skips (its COVERAGE_SKIP), which can't pass instrumented."""
    text = read_file(os.path.join(repo, "Makefile")) or ""
    match = re.search(r"^COVERAGE_SKIP\s*:?=((?:.*\\\n)*.*)$", text, re.MULTILINE)
    return match.group(1).replace("\\\n", " ").split() if match else []


def dev_exec(repo: str) -> str | None:
    """How to run a command in the repo's dev container, when its Compose file has a dev service."""
    for name in ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"):
        if re.search(r"(?m)^  dev:\s*$", read_file(os.path.join(repo, name)) or ""):
            return "docker compose exec -T -e CI=true dev"
    return None


def checks_script(repo: str, out: str, number: int, exec_prefix: str, scope: dict, packages: dict,
                  sql: bool, manifests: bool, coverage: bool) -> str:
    """The checks, as a POSIX sh script run on the host from anywhere."""
    q = shlex.quote
    args = ["--workspace"] if scope["workspace"] else [a for name in scope["packages"] for a in ("-p", name)]
    doc_args = ["--workspace"] if scope["workspace"] else [a for name in scope["packages"] if packages[name]["lib"] for a in ("-p", name)]
    run = exec_prefix
    lines = [
        "#!/bin/sh",
        f"# The checks of /ace-review round {number}, written by prepare.py. Run as: sh checks.sh > checks.txt 2>&1",
        "# Each step prints its command, its output and exit[<step>]=<code>; a failed step doesn't stop the rest.",
        f"cd {q(repo)} || exit 2",
        'step() { name=$1; shift; echo "== $name: $*"; "$@"; echo "exit[$name]=$?"; }',
        f"if ! {run} true; then echo 'exit[container]=1: the dev container is not running (make up)'; exit 3; fi",
        f"step disk {run} df -h target",
        f"step fmt {run} cargo fmt --all --check",
    ]
    if args:
        lines.append(f"step clippy {run} cargo clippy --locked --all-targets {' '.join(args)} -- -D warnings")
        lines.append(f"step nextest {run} cargo nextest run --locked --no-fail-fast {' '.join(args)}")
        if doc_args:
            lines.append(f"step doctests {run} cargo test --doc --locked {' '.join(doc_args)}")
    if sql:
        if os.path.exists(os.path.join(repo, "tools", "sqlx-check")):
            lines.append(f"step sqlx {run} tools/sqlx-check")
        else:
            lines.append(f"step sqlx {run} sh -c 'cargo sqlx migrate run && cargo sqlx prepare --workspace --check'")
    if manifests and "ace-layering" in packages:
        lines.append(f"step layering {run} cargo run --locked --quiet -p ace-layering")
    if coverage and args:
        skips = " ".join(f"--skip {q(t)}" for t in coverage_skips(repo))
        lcov = os.path.join(out, "coverage.lcov")
        # as make coverage builds it: no sccache, which can't cache instrumented builds, and no debug info
        cov_run = run.replace(" exec -T ", " exec -T -e RUSTC_WRAPPER= -e CARGO_PROFILE_DEV_DEBUG=false ", 1)
        lines += [
            f"free=$({run} df -Pk target | awk 'NR==2 {{print int($4 / 1048576)}}')",
            f"if [ \"${{free:-0}}\" -lt {COVERAGE_MIN_FREE_GB} ]; then",
            f"  echo \"exit[coverage]=2: Docker has ${{free}} GB free; coverage needs {COVERAGE_MIN_FREE_GB} GB\"",
            "else",
            f"  step coverage {cov_run} cargo llvm-cov --locked --no-fail-fast --no-report {' '.join(args)} -- {skips}".rstrip(" -"),
            f"  {cov_run} cargo llvm-cov report --lcov > {q(lcov)}; echo \"exit[coverage-report]=$?\"",
            f"  {cov_run} cargo llvm-cov clean --workspace",
            "fi",
        ]
    lines.append("echo '== done'")
    return "\n".join(lines) + "\n"


# --- rounds ---------------------------------------------------------------------------


def snapshot_tree(repo: str) -> str:
    """The tree object of the working tree as it is now, untracked files included.

    Built in a copy of the index, so the real one is untouched. The objects it writes are
    unreferenced, and when git gc prunes one, a later round only loses its delta.
    """
    index = os.path.join(repo, git(repo, "rev-parse", "--git-path", "index").strip())
    with tempfile.TemporaryDirectory() as tmp:
        tmp_index = os.path.join(tmp, "index")
        if os.path.exists(index):
            # the copy keeps the stat cache, so only files that changed are hashed. It must
            # keep the index's mtime too: git rehashes an entry written in the same second
            # as the index ("racily clean") only when the index looks that old
            shutil.copy2(index, tmp_index)
        env = {**os.environ, "GIT_INDEX_FILE": tmp_index}
        for args in (["add", "-A"], ["write-tree"]):
            result = subprocess.run(["git", "-C", repo, *args], env=env, capture_output=True, text=True)
            if result.returncode != 0:
                sys.exit(f"git {' '.join(args)} failed in {repo}: {result.stderr.strip()}")
        return result.stdout.strip()


def safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")


def round_dirs(state: str) -> list[tuple[int, str]]:
    found = []
    if os.path.isdir(state):
        for name in os.listdir(state):
            match = re.fullmatch(r"round-(\d+)", name)
            if match:
                found.append((int(match.group(1)), os.path.join(state, name)))
    return sorted(found)


def finished(round_dir: str) -> bool:
    return os.path.exists(os.path.join(round_dir, "summary.json"))


def next_round(state: str) -> tuple[int, str, str | None]:
    """The new round's number and bundle directory, and the last finished round's."""
    rounds = round_dirs(state)
    done = [path for _, path in rounds if finished(path)]
    if rounds and not finished(rounds[-1][1]):
        number, bundle = rounds[-1]
        shutil.rmtree(bundle)
    else:
        number = rounds[-1][0] + 1 if rounds else 1
        bundle = os.path.join(state, f"round-{number}")
    os.makedirs(bundle)
    return number, bundle, done[-1] if done else None


def build_previous(state: str) -> tuple[list[dict], dict[str, str], list[dict]]:
    """Every finding of the finished rounds with its status, the user's decision on each
    rule-change digest, and the number of new findings per round."""
    ledger: dict[str, dict] = {}
    rule_answers: dict[str, str] = {}
    history = []
    for number, path in round_dirs(state):
        if not finished(path):
            continue
        counts = {"round": number, "blocker": 0, "fix-first": 0, "nit": 0}
        for finding in load_json(os.path.join(path, "verified.json"), []):
            blocking = finding.get("origin") == "new" and finding.get("bucket") == "act on"
            ledger[finding["id"]] = {**finding, "round": number, "status": "open" if blocking else "seen"}
            if finding.get("origin") == "new" and finding.get("severity") in counts:
                counts[finding["severity"]] += 1
        for carried in load_json(os.path.join(path, "carried.json"), []):
            entry = ledger.get(carried.get("id"))
            if entry and entry["status"] in ("open", "fixed"):
                entry["status"] = carried["status"]
        for answer in load_json(os.path.join(path, "answers.json"), []):
            if answer["id"] == "rules":
                rule_answers[answer["digest"]] = answer["answer"]
            elif answer["id"] in ledger:
                entry = ledger[answer["id"]]
                entry["answer"] = answer["answer"]
                if answer.get("note"):
                    entry["answer_note"] = answer["note"]
                if answer["answer"] in DISMISSING_ANSWERS:
                    entry["status"] = "dismissed"
        history.append(counts)
    return list(ledger.values()), rule_answers, history


# --- rules ----------------------------------------------------------------------------


def section(text: str | None, heading: str) -> str:
    """One '## ' section of a Markdown file, heading included, or '' if it has none."""
    out, inside = [], False
    for line in (text or "").splitlines(keepends=True):
        if line.startswith("## "):
            inside = line.rstrip() == heading
        if inside:
            out.append(line)
    return "".join(out)


def read_rules(read) -> tuple[str, str | None]:
    """The name and text of the rules file that read(path) finds first; (AGENTS.md, None) if none."""
    for name in RULES_FILES:
        text = read(name)
        if text is not None:
            return name, text
    return RULES_FILES[0], None


def pinned_tags(tree_files: list[str], head_text) -> list[str]:
    """The ace-rs tags a site workspace's manifests pin, newest-looking last."""
    tags = set()
    for path in tree_files:
        if path == "Cargo.toml" or path.endswith("/Cargo.toml"):
            for match in re.finditer(r'git\s*=\s*"[^"]*ace-rs[^"]*"[^}\n]*?tag\s*=\s*"([^"]+)"', head_text(path) or ""):
                tags.add(match.group(1))
    return sorted(tags)


def snapshot_rules(ace_rs: str, repo: str, kind: str, rules_rev: str | None, out: str, tags: list[str],
                   accepted: str | None = None) -> dict[str, str]:
    """Write the AGENTS.md files the change is judged by into out/rules/.

    ace-rs's copy comes from the base for a change to ace-rs, so a change that edits it isn't
    judged by its own edit until the user accepts it: then `accepted` is the edited copy. For
    a site, ace-rs's copy comes from the tag the site pins, where this checkout has it, and the
    site's own from its base. The skill's files are used from the working tree: they have to
    match the SKILL.md that is running, so rule_changes() reports a change to them instead.
    """
    rules = os.path.join(out, "rules")
    os.makedirs(rules)
    sources = {}
    if kind == "ace-rs":
        if accepted is not None:
            text, origin = accepted, "working tree (rule changes accepted)"
        else:
            text = read_rules(lambda path: show(repo, rules_rev, path))[1] if rules_rev else None
            origin = rules_rev
            if text is None:
                # a base from before the rules were written down: the checkout's are all there are
                text = read_rules(lambda path: read_file(os.path.join(ace_rs, path)))[1]
                origin = f"working tree of {ace_rs} ({rules_rev} has no AGENTS.md)" if text is not None else None
    else:
        text, origin = None, None
        for tag in reversed(tags):
            text = show(ace_rs, tag, "AGENTS.md")
            if text is not None:
                origin = f"ace-rs {tag}"
                break
        if text is None:
            base = detect_base(ace_rs)
            text = show(ace_rs, base, "AGENTS.md") if base else None
            origin = f"ace-rs {base} (the pinned tag isn't in this checkout)" if text is not None else None
        if text is None:
            text = read_file(os.path.join(ace_rs, "AGENTS.md"))
            origin = f"working tree of {ace_rs} (neither the pinned tag nor the base has AGENTS.md)" if text is not None else None
        site_text = accepted if accepted is not None else (
            read_rules(lambda path: show(repo, rules_rev, path))[1] if rules_rev else None)
        if site_text is not None:
            with open(os.path.join(rules, "repo-AGENTS.md"), "w") as fp:
                fp.write(site_text)
            sources["repo-AGENTS.md"] = "working tree (rule changes accepted)" if accepted is not None else rules_rev
    if text is not None:
        with open(os.path.join(rules, "AGENTS.md"), "w") as fp:
            fp.write(text)
        sources["AGENTS.md"] = origin
    return sources


def unified(path: str, before: str | None, after: str | None) -> list[str]:
    lines = difflib.unified_diff((before or "").splitlines(keepends=True), (after or "").splitlines(keepends=True), f"a/{path}", f"b/{path}")
    return [line if line.endswith("\n") else line + "\n" for line in lines]


def rule_changes(repo: str, kind: str, merge_base: str, changed_paths: set[str], head_text) -> tuple[list[str], str]:
    """What the change does to the rules it is reviewed by: a name per change, and a patch."""
    names, patch = [], []
    if changed_paths & set(RULES_FILES):
        before = read_rules(lambda path: show(repo, merge_base, path))[1]
        name, after = read_rules(head_text)
        # a site's rules file has no known rule sections, so all of it counts
        for heading in RULE_SECTIONS if kind == "ace-rs" else (None,):
            old = section(before, heading) if heading else before
            new = section(after, heading) if heading else after
            if (old or "") != (new or ""):
                names.append(f"{name} § {heading.removeprefix('## ')}" if heading else name)
                patch.extend(unified(name, old, new))
    if kind == "ace-rs":
        for path in sorted(p for p in changed_paths if p.startswith(SKILL_DIR + "/")):
            names.append(path)
            patch.extend(unified(path, show(repo, merge_base, path), head_text(path)))
    return names, "".join(patch)


def related_docs(repo: str, rev: str, changed_paths: set[str]) -> str:
    """Lines of the base's Markdown that name a changed file, a few per file."""
    out = []
    for path in sorted(changed_paths):
        if path.endswith(".md") or "/" not in path:
            continue
        found = git(repo, "grep", "-n", "-F", "-e", path, rev, "--", "*.md", check=False).splitlines()
        found = [line.removeprefix(f"{rev}:") for line in found if not line.removeprefix(f"{rev}:").startswith(DOC_SKIP)]
        out += [f"{path}\t{line[:240]}" for line in found[:RELATED_DOC_HITS]]
    return "".join(line + "\n" for line in out)


# --- reading Rust ---------------------------------------------------------------------

RAW_STRING = re.compile(r'(?:b|c)?r(#*)"')
# a run of code that can't start a string, a char literal or a comment
PLAIN = re.compile(r"[^/\"'\nrbc]+")
STRING_BODY = re.compile(r'(?:[^"\\]|\\.)*', re.DOTALL)
CHAR_LITERAL = re.compile(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]{1,6}\}|.)|[^\\'\n])'")


@functools.lru_cache(maxsize=64)
def lex(text: str) -> list[tuple[str, str, str]]:
    """Each line of a Rust file as (code, strings, comments): the code with every string literal
    replaced by "" and comments removed, the text of the strings on the line, and the text of its
    comments. Close enough for line checks; not a parser."""
    lines = text.split("\n")
    code = [[] for _ in lines]
    strs = [[] for _ in lines]
    comm = [[] for _ in lines]
    i, n, line = 0, len(text), 0

    def ident_before(at: int) -> bool:
        return at > 0 and (text[at - 1].isalnum() or text[at - 1] == "_")

    def take(start: int, end: int, into) -> None:
        nonlocal line
        for k, part in enumerate(text[start:end].split("\n")):
            if k:
                line += 1
            into[line].append(part)

    while i < n:
        if m := PLAIN.match(text, i):
            code[line].append(m.group())
            i = m.end()
            continue
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            comm[line].append(text[i + 2:end])
            i = end
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            take(i + 2, max(i + 2, j - 2), comm)
            i = j
        elif (m := RAW_STRING.match(text, i)) and not ident_before(i):
            close = '"' + m.group(1)
            end = text.find(close, m.end())
            end = n if end < 0 else end
            code[line].append('""')
            take(m.end(), end, strs)
            i = end + len(close)
        elif c == '"' or (c in "bc" and text.startswith('"', i + 1) and not ident_before(i)):
            j = i + (1 if c == '"' else 2)
            code[line].append('""')
            end = STRING_BODY.match(text, j).end()
            take(j, end, strs)
            i = end + 1
        elif c == "'" and (m := CHAR_LITERAL.match(text, i)):
            code[line].append("' '")
            i = m.end()
        else:
            code[line].append(c)
            i += 1
    out = []
    for raw, a, b, c in zip(lines, code, strs, comm):
        text = "".join(a)
        # code after a string or comment that began on an earlier line keeps the line's indentation
        if text.strip() and not text[:1].isspace() and raw[:1].isspace():
            text = raw[:indent(raw)] + text
        out.append((text, " ".join(b), " ".join(c)))
    return out


def indent(text: str) -> int:
    return len(text) - len(text.lstrip())


def test_lines(lexed: list[tuple[str, str, str]]) -> set[int]:
    """Line numbers (1-based) inside an item marked #[cfg(test)]: a mod tests { } block, or a function."""
    found = set()
    for i, (code, _, _) in enumerate(lexed):
        if not re.match(r"\s*#\[cfg\(test\)\]", code):
            continue
        j = i + 1
        while j < len(lexed) and (not lexed[j][0].strip() or lexed[j][0].lstrip().startswith("#[")):
            j += 1
        if j >= len(lexed) or not lexed[j][0].rstrip().endswith("{"):
            continue
        depth = indent(lexed[j][0])
        k = j + 1
        while k < len(lexed) and not (lexed[k][0].strip() == "}" and indent(lexed[k][0]) == depth):
            k += 1
        found.update(range(i + 1, k + 2))
    return found


def cfg_test_module(path: str, head_text) -> bool:
    """Whether a source file is a module its parent declares under #[cfg(test)] (mod tests;)."""
    directory, name = os.path.split(path)
    module = os.path.basename(directory) if name == "mod.rs" else name.removesuffix(".rs")
    parent_dir = os.path.dirname(directory) if name == "mod.rs" else directory
    parents = [os.path.join(parent_dir, f) for f in ("lib.rs", "main.rs", "mod.rs")]
    parents.append(parent_dir + ".rs")
    for parent in parents:
        text = head_text(parent)
        if text and re.search(r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(pub(\([^)]*\))?\s+)?mod\s+" + re.escape(module) + r"\s*;", text):
            return True
    return False


def file_kind(path: str, packages: dict, head_text) -> str:
    """test (tests, test support), cli (a binary, a build script, a command crate) or lib."""
    wrapped = "/" + path
    package = owner(path, packages)
    if (re.search(r"/(tests|benches|examples)/", wrapped) or os.path.basename(path) in ("tests.rs", "testing.rs")
            or "/src/tests/" in wrapped or package == "ace-testkit" or cfg_test_module(path, head_text)):
        return "test"
    if (package is None or os.path.basename(path) in ("build.rs", "main.rs") or "/src/bin/" in wrapped
            or package in CLI_CRATES):
        return "cli"
    return "lib"


# --- mechanical leads -----------------------------------------------------------------


def unquote(path: str) -> str:
    """Undo git's C-style quoting of a path with unusual characters."""
    if path.startswith('"') and path.endswith('"'):
        return codecs.escape_decode(path[1:-1].encode())[0].decode("utf-8", "replace")
    return path


def added_lines(diff: str) -> dict[str, set[int]]:
    """New-side line numbers of the lines a diff adds, per file."""
    added: dict[str, set[int]] = {}
    path, line, in_header = None, 0, False
    for text in diff.splitlines():
        if text.startswith("diff --git "):
            path, in_header = None, True
        elif in_header and text.startswith("+++ "):
            target = unquote(text[4:].rstrip("\t"))
            path = None if target == "/dev/null" else target.removeprefix("b/")
        elif match := HUNK.match(text):
            line, in_header = int(match.group(1)), False
        elif path is not None and not in_header:
            if text.startswith("+"):
                added.setdefault(path, set()).add(line)
                line += 1
            elif text.startswith(" "):
                line += 1
    return added


def removed_text(diff: str) -> str:
    """The text of the lines a diff removes."""
    return "\n".join(t[1:] for t in diff.splitlines() if t.startswith("-") and not t.startswith("---"))


WAIT = re.compile(r"\.(?:(?:recv|lock|acquire|acquire_owned|join_next|notified|changed|read|write)\(\)\s*\.await"
                  r"|(?:recv|join|wait)\(\)(?!\s*\.await))|\b\w*handles?\s*\.await|\btask\s*\.await")
NETWORK = re.compile(r"\b(?:TcpStream|UnixStream)::connect\(|\breqwest::get\(|\breqwest::Client::new\(\)")
CLOCK = re.compile(r"\b(?:Utc::now|SystemTime::now|OffsetDateTime::now_utc|Local::now)\(\)")
QUERY_START = re.compile(r"\b(?:sqlx::)?query(?:_as|_scalar|_file|_file_as)?(?:!|::<[^>]*>)?\(|\bQueryBuilder::")
QUERY_END = re.compile(r"\.(?:fetch\w*|execute)\(|;\s*$")
PRINT = re.compile(r"(?<![\w:])(?:e?println|e?print)!\(")
DBG = re.compile(r"(?<![\w:])dbg!\(")
LOG_ERROR = re.compile(r"\b(?:tracing::)?(?:error|warn)!\(")
UNCHAINED = re.compile(r"\{(?:e|err|error|source)\}|(?<![?\w])%(?:e|err|error|source)\b")
SLEEP = re.compile(r"\b(?:tokio::time::sleep|std::thread::sleep|thread::sleep|time::sleep|sleep)\(")
ELAPSED = re.compile(r"elapsed\(\)[\w().]*\s*<=?(?!<)|(?<!>)>=?\s*[\w.:()]*elapsed\(\)")
IGNORE = re.compile(r"#\[ignore\]")
OFFSET_SQL = re.compile(r"\bOFFSET\b|\boffset\s+(?:\$\d+|\d+|\?)")
DB_CALL = re.compile(r"\.(?:fetch_one|fetch_optional|fetch_all|fetch|execute)\(")
LOOP = re.compile(r"^\s*(?:(?:'\w+:\s*)?(?:for\b.*\bin\b|while\b|loop\b))")
FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"\w+\"\s+)?fn\s+(\w+)")
TODO = re.compile(r"(?<![\w:])(?:todo|unimplemented)!\(")
SQL_WORDS = re.compile(r"\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM|WHERE)\b")
SHELL = re.compile(r'Command::new\(\s*"(?:/bin/|/usr/bin/)?(?:sh|bash|zsh|dash)"\s*\)')


def commented(lexed, index: int, above: int = 1) -> bool:
    """Whether the line, or one of the `above` lines right before it, has a comment."""
    return any(lexed[k][2].strip() for k in range(max(0, index - above), index + 1))


def in_loop(lexed, index: int) -> bool:
    """Whether a line sits in a for, while or loop body of its function, by rustfmt's indentation."""
    current = indent(lexed[index][0])
    for k in range(index - 1, -1, -1):
        code = lexed[k][0]
        if not code.strip() or indent(code) >= current:
            continue
        if FN.match(code) or re.match(r"\s*(impl|mod|trait)\b", code):
            return False
        if LOOP.match(code):
            return True
        current = indent(code)
        if current == 0:
            return False
    return False


def in_select(lexed, index: int) -> bool:
    """Whether a line is an arm of a select! a few lines up (its timeout or cancel arm bounds it)."""
    current = indent(lexed[index][0])
    for k in range(index - 1, max(-1, index - 30), -1):
        code = lexed[k][0]
        if code.strip() and indent(code) < current:
            if "select!" in code or "select_biased!" in code:
                return True
            current = indent(code)
    return False


def assigned(lexed, index: int) -> bool:
    """Whether the statement a line ends is a let, an assignment or a return, by the lines back to
    the one before it."""
    parts = [lexed[index][0]]
    for k in range(index - 1, max(-1, index - 12), -1):
        code = lexed[k][0].rstrip()
        if code.endswith((";", "{", "}")) or not code:
            break
        parts.append(code)
    text = " ".join(reversed(parts))
    return re.search(r"\blet\b|\breturn\b|(?<![=!<>])=(?![=>])", text) is not None


def macro_call(lexed, index: int, start: int, limit: int = 12) -> str:
    """The code and strings of a macro call from its opening parenthesis (at `start` of line
    `index`) to the one that closes it."""
    depth, parts = 1, []
    for k in range(index, min(len(lexed), index + limit)):
        code = lexed[k][0][start:] if k == index else lexed[k][0]
        end = None
        for pos, ch in enumerate(code):
            depth += ch == "("
            depth -= ch == ")"
            if depth == 0:
                end = pos
                break
        parts.append(code[:end] if end is not None else code)
        parts.append(lexed[k][1])
        if end is not None:
            break
    return " ".join(parts)


def hidden_source(lexed, index: int) -> str | None:
    """For a thiserror #[error("...")] line, the source field its message doesn't name, if any:
    a #[from] or #[source] field, or one named source."""
    message = " ".join(lexed[k][1] for k in range(index, min(len(lexed), index + 3)) if k == index or lexed[k][0].lstrip().startswith(('"', ')')))
    k = index + 1
    while k < len(lexed) and lexed[k][0].lstrip().startswith(("#[", '"', ")")) and "#[error(" not in lexed[k][0]:
        k += 1
    if k >= len(lexed):
        return None
    head = lexed[k][0]
    fields = []
    if re.search(r"\w+\s*\(", head):
        inner = head[head.find("(") + 1:]
        if re.search(r"#\[(from|source)\]", inner):
            fields.append("0")
    elif head.rstrip().endswith("{"):
        attr = False
        for j in range(k + 1, min(len(lexed), k + 15)):
            line = lexed[j][0].strip()
            if line.startswith("}"):
                break
            if re.match(r"#\[(from|source)\]", line):
                attr = True
                line = re.sub(r"^#\[(from|source)\]\s*", "", line)
                if not line:
                    continue
            if m := re.match(r"(\w+)\s*:", line):
                if attr or m.group(1) == "source":
                    fields.append(m.group(1))
                attr = False
    for field in fields:
        if not re.search(r"\{\.?" + re.escape(field) + r"\b|\{\}", message):
            return field
    return None


def statement(lexed, index: int, back: int, forward: int) -> str:
    return " ".join(lexed[k][0] for k in range(max(0, index - back), min(len(lexed), index + forward + 1)))


def scan_rust(path: str, source: str, added: set[int], kind: str) -> list[dict]:
    lexed = lex(source)
    tests = test_lines(lexed) if kind != "test" else set(range(1, len(lexed) + 1))
    leads = []
    raw = source.split("\n")
    open_query = -1
    # a typed error's Display names its source here (error-hides-source checks that), so only an
    # anyhow error logged with {e} loses its chain
    uses_anyhow = "anyhow" in source

    def lead(index: int, check: str, dimension: str) -> None:
        leads.append({"check": check, "dimension": dimension, "file": path, "line": index + 1, "text": raw[index].strip()[:200]})

    for index, (code, strs, _) in enumerate(lexed):
        if QUERY_START.search(code):
            open_query = index
        number = index + 1
        if number not in added:
            if open_query >= 0 and QUERY_END.search(code):
                open_query = -1
            continue
        test = number in tests
        lib = kind == "lib" and not test
        if IGNORE.search(code):
            lead(index, "ignore-without-reason", "tests")
        if test:
            # in a loop, a sleep is a poll's interval and a bound on elapsed() is its deadline
            polling = in_loop(lexed, index)
            if SLEEP.search(code) and not polling and not commented(lexed, index):
                lead(index, "sleep-in-test", "tests")
            if ELAPSED.search(code) and not polling and "assert" in statement(lexed, index, 3, 0) and not commented(lexed, index):
                lead(index, "wall-clock-assert", "tests")
        else:
            if WAIT.search(code) and lib and "timeout(" not in statement(lexed, index, 3, 0) \
                    and not commented(lexed, index) and not in_select(lexed, index):
                lead(index, "unbounded-wait", "uptime")
            if NETWORK.search(code) and lib and "timeout" not in statement(lexed, index, 1, 3) and not commented(lexed, index):
                lead(index, "no-timeout", "uptime")
            if CLOCK.search(code) and (".bind(" in code or open_query >= 0) and not commented(lexed, index):
                lead(index, "app-clock", "uptime")
            if PRINT.search(code) and lib and not commented(lexed, index):
                lead(index, "print-in-library", "logging")
            if DBG.search(code):
                lead(index, "dbg", "logging")
            if uses_anyhow and (m := LOG_ERROR.search(code)) and UNCHAINED.search(macro_call(lexed, index, m.end())) \
                    and not commented(lexed, index, 1):
                lead(index, "error-without-chain", "logging")
            if "#[error(" in code and "transparent" not in code and hidden_source(lexed, index):
                lead(index, "error-hides-source", "logging")
            if re.search(r"\.ok\(\)\s*;\s*$", code) and not assigned(lexed, index) and not commented(lexed, index):
                lead(index, "dropped-error", "logging")
            if DB_CALL.search(code) and lib and in_loop(lexed, index) and not commented(lexed, index):
                lead(index, "query-in-loop", "performance")
            if TODO.search(code):
                lead(index, "todo", "correctness")
            if "format!(" in code and SQL_WORDS.search(strs) and not commented(lexed, index):
                lead(index, "sql-format", "correctness")
            if "Command::new(" in code and SHELL.search(raw[index]):
                lead(index, "shell-command", "correctness")
        if OFFSET_SQL.search(strs) and (SQL_WORDS.search(strs) or "LIMIT" in strs or open_query >= 0):
            lead(index, "offset-paging", "performance")
        if open_query >= 0 and QUERY_END.search(code):
            open_query = -1
    return leads


# --- migrations -----------------------------------------------------------------------


def sql_statements(text: str) -> list[tuple[int, int, str, bool]]:
    """Each statement of a SQL file: its first and last line (1-based), its text without comments,
    and whether a comment sits right above it."""
    out, start, buf, note, prev_comment = [], None, [], False, False
    for number, line in enumerate(text.split("\n"), 1):
        bare = line.split("--", 1)[0]
        if start is None:
            if not bare.strip():
                prev_comment = line.strip().startswith("--") or (prev_comment and not line.strip())
                continue
            start, note = number, prev_comment
        buf.append(bare)
        if bare.rstrip().endswith(";"):
            out.append((start, number, " ".join(buf), note))
            start, buf, prev_comment = None, [], False
    if buf:
        out.append((start, len(text.split("\n")), " ".join(buf), note))
    return out


def scan_migration(path: str, source: str, added: set[int]) -> list[dict]:
    statements = sql_statements(source)
    created = {m.group(1).lower() for _, _, s, _ in statements
               for m in [re.search(r"\bCREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w.\"]+)", s, re.IGNORECASE)] if m}
    bounded = re.search(r"\block_timeout\b", source, re.IGNORECASE) is not None
    raw = source.split("\n")
    leads = []
    for first, last, text, _ in statements:
        if not any(n in added for n in range(first, last + 1)):
            continue
        flat = " ".join(text.split())
        table = None
        if m := re.search(r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY)(?:IF\s+NOT\s+EXISTS\s+)?[\w\"]*\s*ON\s+(?:ONLY\s+)?([\w.\"]+)", flat, re.IGNORECASE):
            table = m.group(1)
        elif m := re.search(r"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([\w.\"]+)\s+.*\b(?:ALTER\s+COLUMN\s+\S+\s+(?:SET\s+DATA\s+)?TYPE|SET\s+NOT\s+NULL"
                            r"|ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?\S+\s+[^,]*\bNOT\s+NULL\b(?![^,]*\bDEFAULT\b)"
                            r"|ADD\s+(?:CONSTRAINT\s+\S+\s+)?(?:FOREIGN\s+KEY|CHECK|UNIQUE|PRIMARY\s+KEY|EXCLUDE)(?![^,]*\bNOT\s+VALID\b))", flat, re.IGNORECASE):
            table = m.group(1)
        elif m := re.search(r"^\s*(?:UPDATE\s+(?:ONLY\s+)?([\w.\"]+)\s+(?:AS\s+)?\w*\s*SET\b|DELETE\s+FROM\s+(?:ONLY\s+)?([\w.\"]+))", flat, re.IGNORECASE):
            table = m.group(1) or m.group(2)
        if table and table.lower() not in created and not bounded:
            leads.append({"check": "blocking-migration", "dimension": "uptime", "file": path, "line": first,
                          "text": raw[first - 1].strip()[:200]})
        if OFFSET_SQL.search(flat) and re.search(r"\bSELECT\b", flat, re.IGNORECASE):
            leads.append({"check": "offset-paging", "dimension": "performance", "file": path, "line": first, "text": raw[first - 1].strip()[:200]})
    return leads


def migration_leads(repo: str, merge_base: str, base: str | None, changed: list[tuple[str, str, str]]) -> list[dict]:
    """Applied migrations the change edits, and new ones numbered out of order."""
    leads = []
    existing: dict[str, set[int]] = {}
    for rev in {merge_base, base} - {None}:
        for path in git(repo, "ls-tree", "-r", "--name-only", rev, check=False).splitlines():
            if m := MIGRATION.search(path):
                existing.setdefault(os.path.dirname(path), set()).add(int(m.group(2)))
    new_numbers: dict[str, list[int]] = {}
    for status, old, path in changed:
        if MIGRATION.search(old) and status[0] in "MDR" and show(repo, merge_base, old) is not None:
            leads.append({"check": "edited-migration", "dimension": "uptime", "file": old, "line": 1,
                          "text": f"{'deleted' if status[0] == 'D' else 'renamed' if status[0] == 'R' else 'edited'}: {old}"})
        if status[0] in "AR" and (m := MIGRATION.search(path)):
            new_numbers.setdefault(os.path.dirname(path), []).append(int(m.group(2)))
            directory, number = os.path.dirname(path), int(m.group(2))
            highest = max(existing.get(directory, {0}))
            if number <= highest or new_numbers[directory].count(number) > 1:
                leads.append({"check": "migration-order", "dimension": "correctness", "file": path, "line": 1,
                              "text": f"number {number}; the base's highest is {highest}"})
    return leads


# --- copied functions -----------------------------------------------------------------


def rust_functions(text: str):
    """(name, first line, last line, key, anchor) of each function: the key is its parameters and
    body, strings included, with whitespace and its name taken out; the anchor is its longest line
    as written, for git grep to find the files that may hold a copy."""
    lexed = lex(text)
    raw = text.split("\n")
    for i, (code, _, _) in enumerate(lexed):
        m = FN.match(code)
        if not m:
            continue
        attrs = " ".join(lexed[k][0] for k in range(max(0, i - 3), i))
        if re.search(r"#\[(?:\w+::)*test\b", attrs):
            continue
        depth, started, body, j = 0, False, [], i
        while j < len(lexed):
            text = lexed[j][0]
            if not started and ";" in text and "{" not in text:
                break  # a declaration with no body
            for ch in text:
                if ch == "{":
                    depth, started = depth + 1, True
                elif ch == "}":
                    depth -= 1
            body.append(text + " " + lexed[j][1])
            if started and depth <= 0:
                break
            j += 1
        if not started or depth > 0:
            continue
        joined = " ".join(body)
        inner = joined[joined.find("{") + 1:]
        if inner.count(";") < COPY_MIN_STATEMENTS:
            continue
        # the parameters and return type, from just after the name to the body
        signature = joined[joined.find(m.group(1)) + len(m.group(1)):joined.find("{")]
        key = re.sub(r"\s+", "", signature + "|" + inner)
        anchor = max((line.strip() for line in raw[i + 1:j]), key=len, default="")
        yield m.group(1), i + 1, j + 1, key, anchor


def read_tree_files(repo: str, tree: str, paths: list[str]) -> dict[str, str]:
    """The text of several files of a tree, through one git cat-file."""
    if not paths:
        return {}
    request = "".join(f"{tree}:{p}\n" for p in paths).encode()
    data = subprocess.run(["git", "-C", repo, "cat-file", "--batch"], input=request, capture_output=True).stdout
    out, pos = {}, 0
    for path in paths:
        end = data.index(b"\n", pos)
        header = data[pos:end].decode()
        pos = end + 1
        if header.endswith(" missing"):
            continue
        size = int(header.split()[2])
        out[path] = data[pos:pos + size].decode("utf-8", "replace")
        pos += size + 1
    return out


def copied_functions(repo: str, tree: str, added: dict[str, set[int]], head_text) -> list[dict]:
    """Functions the change adds whose parameters and body repeat another function in the repo."""
    new = []
    for path, lines in added.items():
        if path.endswith(".rs") and lines:
            for name, first, _, key, anchor in rust_functions(head_text(path) or ""):
                if first in lines and len(anchor) >= COPY_ANCHOR_MIN:
                    new.append((path, name, first, key, anchor))
    if not new:
        return []
    args = [a for *_, anchor in new for a in ("-e", anchor)]
    found_files = git(repo, "grep", "-l", "-F", *args, tree, "--", "*.rs", check=False).splitlines()
    candidates = sorted({line.split(":", 1)[1] for line in found_files if ":" in line})
    texts = read_tree_files(repo, tree, candidates)
    wanted = {key for *_, key, _ in new}
    found: dict[str, list[tuple[str, int, str]]] = {}
    for path, text in texts.items():
        for name, first, _, key, _ in rust_functions(text):
            if key in wanted:
                found.setdefault(key, []).append((path, first, name))
    leads = []
    for path, name, first, key, _ in new:
        others = [o for o in found.get(key, []) if o[:2] != (path, first)]
        if others:
            other_path, other_line, other_name = others[0]
            leads.append({"check": "copied-function", "dimension": "design", "file": path, "line": first,
                          "text": f"{name} repeats {other_path}:{other_line} {other_name}"})
    return leads


# --- stale references -----------------------------------------------------------------

ITEM = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+|const\s+|unsafe\s+)*(?:fn|struct|enum|trait|type|const|static|mod)\s+(\w+)", re.MULTILINE)
ENV_VAR = re.compile(r"\bACE_RS_[A-Z0-9_]{3,}\b")


def rust_items(source: str | None) -> set[str]:
    if not source:
        return set()
    return set(ITEM.findall("\n".join(code for code, _, _ in lex(source))))


def distinctive(name: str) -> bool:
    """Whether a name is specific enough that a doc line naming it means this one."""
    core = name.strip("_")
    return (len(core) >= 6 and not core.startswith("test") and not core.isupper()
            and ("_" in core or re.search(r"[a-z][A-Z]", core) is not None))


def yaml_keys(text: str | None) -> set[str]:
    """The dotted key paths of a YAML file's mappings, by indentation. Lists and flow mappings are
    passed over: enough to see a key go, not a YAML parser."""
    keys, stack = set(), []
    for line in (text or "").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^(\s*)([A-Za-z_][\w-]*)\s*:(\s|$)", line)
        if not m:
            continue
        depth = len(m.group(1))
        while stack and stack[-1][0] >= depth:
            stack.pop()
        path = ".".join([k for _, k in stack] + [m.group(2)])
        keys.add(path)
        stack.append((depth, m.group(2)))
    return keys


def name_ref(kind: str, term: str, pattern: str) -> dict:
    return {"removed": kind, "ref": term, "pattern": re.compile(pattern)}


def path_ref(kind: str, path: str) -> dict:
    tail = "" if path.endswith("/") else r"(?![\w-])"
    return name_ref(kind, path, r"(?<![\w/.-])" + re.escape(path) + tail)


def removed_refs(repo: str, tree: str, merge_base: str, changed: list[tuple[str, str, str]], diff: str, head_text) -> list[dict]:
    """A doc-line pattern for every path, Rust item, ACE_RS_ variable and YAML key the change removes."""
    # sqlx's query files are named by hash, which no doc names
    removed_files = [old for status, old, _ in changed if status[0] in "DR" and not old.startswith(".sqlx/")]
    present = set(git(repo, "ls-tree", "-r", "-t", "--name-only", tree).splitlines())
    gone = set()
    for old in removed_files:
        parent = os.path.dirname(old)
        while parent and parent not in present:
            gone.add(parent)
            parent = os.path.dirname(parent)
    gone_dirs = sorted(d for d in gone if os.path.dirname(d) not in gone)

    refs = [path_ref("directory", d + "/") for d in gone_dirs]
    refs += [path_ref("file", old) for old in removed_files if not any(old.startswith(d + "/") for d in gone_dirs)]

    names = set()
    for status, old, path in changed:
        if old.endswith(".rs"):
            after = set() if status[0] == "D" else rust_items(head_text(path))
            names |= {n for n in rust_items(show(repo, merge_base, old)) - after if distinctive(n)}
    if names:
        # a name that moved to another file still exists and isn't stale
        pattern = r"(fn|struct|enum|trait|type|const|static|mod)[[:space:]]+(" + "|".join(sorted(names)) + r")\b"
        found = git(repo, "grep", "-h", "-E", pattern, tree, "--", "*.rs", check=False)
        names -= set(re.findall(r"(?:fn|struct|enum|trait|type|const|static|mod)\s+(\w+)", found))
    # docs here name a Rust item in backticks; a bare word is as often ace3's name for the same thing
    refs += [name_ref("Rust item", n, r"`[^`]*\b" + re.escape(n) + r"\b[^`]*`") for n in sorted(names)]

    variables = set(ENV_VAR.findall(removed_text(diff)))
    if variables:
        still = git(repo, "grep", "-h", "-o", "-E", "|".join(sorted(variables)), tree, check=False)
        variables -= set(ENV_VAR.findall(still))
    refs += [name_ref("variable", v, r"\b" + re.escape(v) + r"\b") for v in sorted(variables)]

    for status, old, path in changed:
        if not old.endswith((".yaml", ".yml")) or old.startswith(DOC_SKIP):
            continue
        after = set() if status[0] == "D" else yaml_keys(head_text(path))
        keys = yaml_keys(show(repo, merge_base, old)) - after
        for key in sorted(k for k in keys if k.rpartition(".")[0] not in keys):
            leaf = key.rsplit(".", 1)[-1]
            if distinctive(leaf):
                refs.append(name_ref("YAML key", f"{leaf}:", r"(?<![\w.])" + re.escape(leaf) + r":"))
                if "." in key:
                    tail = ".".join(key.split(".")[-2:])
                    refs.append(name_ref("YAML key", tail, r"(?<![\w.])" + re.escape(tail) + r"(?!\w)"))
    return refs


def stale_references(refs: list[dict], docs: list[str], head_text, added: dict[str, set[int]]) -> list[dict]:
    """Doc lines naming something the change removes, except lines the change itself writes."""
    leads, hits = [], {}
    for doc in docs:
        for number, line in enumerate((head_text(doc) or "").splitlines(), 1):
            if number in added.get(doc, ()):
                continue
            ref = next((r for r in refs if r["pattern"].search(line)), None)
            if ref:
                hits[ref["ref"]] = hits.get(ref["ref"], 0) + 1
                if hits[ref["ref"]] <= STALE_HITS_PER_REF:
                    leads.append({"check": "stale-reference", "dimension": "design", "file": doc, "line": number,
                                  "text": line.strip()[:200], "ref": ref["ref"], "removed": ref["removed"]})
    for lead in leads:
        lead["hits"] = hits[lead["ref"]]
    return leads


# --- all the leads --------------------------------------------------------------------


def undeclared_tests(changed: list[tuple[str, str, str]], head_text) -> list[dict]:
    """Test files the change adds beside a tests/main.rs that doesn't declare them."""
    leads = []
    for status, _, path in changed:
        if status[0] not in "AR":
            continue
        m = re.match(r"^(.*?/)?tests/(\w+)(?:\.rs|/mod\.rs)$", path)
        if not m or m.group(2) == "main":
            continue
        main = head_text(f"{m.group(1) or ''}tests/main.rs")
        if main is not None and not re.search(r"(?m)^\s*(?:#\[[^\]]*\]\s*)*mod\s+" + m.group(2) + r"\s*;", main):
            leads.append({"check": "undeclared-test-file", "dimension": "tests", "file": path, "line": 1,
                          "text": f"tests/main.rs has no `mod {m.group(2)};`"})
    return leads


def sqlx_data_lead(repo: str, tree: str, changed: list[tuple[str, str, str]], added: dict[str, set[int]], head_text) -> list[dict]:
    """A query macro the change adds or edits with no change to .sqlx/, in a repo that keeps one."""
    paths = {p for _, _, p in changed}
    if any(p.startswith(".sqlx/") for p in paths) or not git(repo, "ls-tree", "--name-only", tree, ".sqlx", check=False).strip():
        return []
    for path, lines in sorted(added.items()):
        if path.endswith(".rs") and lines:
            for number, line in enumerate((head_text(path) or "").split("\n"), 1):
                if number in lines and re.search(r"\bquery(?:_as|_scalar|_file|_file_as)?!\(", line):
                    return [{"check": "sqlx-data", "dimension": "correctness", "file": path, "line": number, "text": line.strip()[:200]}]
    return []


def find_leads(repo: str, tree: str, merge_base: str, base: str | None, changed: list[tuple[str, str, str]], head_text,
               packages: dict, diff: str, full_added: dict[str, set[int]], scan_added: dict[str, set[int]]) -> list[dict]:
    """The leads among the lines of scan_added that the change adds, and the doc lines left naming what it removes."""
    added = {path: full_added.get(path, set()) & lines for path, lines in scan_added.items()}
    scan_paths = {p for p, lines in added.items() if lines}
    leads = []
    for status, _, path in changed:
        if status[0] == "D" or path not in scan_paths:
            continue
        if path.endswith(".rs"):
            leads.extend(scan_rust(path, head_text(path) or "", added[path], file_kind(path, packages, head_text)))
        elif MIGRATION.search(path):
            leads.extend(scan_migration(path, head_text(path) or "", added[path]))
    scanned = [c for c in changed if c[2] in scan_paths or c[0][0] == "D"]
    leads.extend(migration_leads(repo, merge_base, base, scanned))
    leads.extend(undeclared_tests(scanned, head_text))
    leads.extend(sqlx_data_lead(repo, tree, scanned, added, head_text))
    leads.extend(copied_functions(repo, tree, added, head_text))
    refs = removed_refs(repo, tree, merge_base, changed, diff, head_text)
    if refs:
        docs = [p for p in git(repo, "ls-tree", "-r", "--name-only", tree).splitlines()
                if p.endswith(".md") and not p.startswith(DOC_SKIP) and not os.path.basename(p).startswith("CHANGELOG")]
        leads.extend(stale_references(refs, docs, head_text, full_added))
    return leads


def check(repo: str, tree: str, merge_base: str, base: str | None, changed: list[tuple[str, str, str]], diff: str,
          head_text, packages: dict) -> int:
    """Print what the mechanical checks find in the lines the change adds, each with its fix; 1 if anything."""
    added = added_lines(diff)
    leads = sorted(find_leads(repo, tree, merge_base, base, changed, head_text, packages, diff, added, added),
                   key=lambda lead: (lead["file"], lead["line"]))
    found = [f"{lead['file']}:{lead['line']}  {lead['check']}  {lead['text']}\n    fix: {CHECK_FIXES[lead['check']]}" for lead in leads]
    print("\n".join(found + [f"{len(found)} line(s) to fix or justify" if found else "nothing found"]))
    return 1 if found else 0


# --- main -----------------------------------------------------------------------------


def write(out: str, name: str, content) -> None:
    with open(os.path.join(out, name), "w") as fp:
        if isinstance(content, str):
            fp.write(content)
        else:
            json.dump(content, fp, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", help="list the ace-rs checkout and its worktrees with their state")
    parser.add_argument("--repo", default=None, help="the repo under review (default: the ace-rs checkout this script is in)")
    parser.add_argument("--base", help="base ref (default: origin/HEAD, main, master)")
    parser.add_argument("--range", help="explicit A..B range instead of merge-base..HEAD")
    parser.add_argument("--full", action="store_true", help="review the whole change, not only what changed since the last round")
    parser.add_argument("--coverage", action="store_true",
                        help=f"add an instrumented run of the tests in scope to checks.sh, for changed-line coverage (needs {COVERAGE_MIN_FREE_GB} GB free on Docker's disk)")
    parser.add_argument("--exec", dest="exec_prefix", help="how to run a command in the repo's dev container (default: docker compose exec -T -e CI=true dev, when its Compose file has a dev service)")
    parser.add_argument("--state-dir", default=None, help="where rounds go (default: local/ace-review in the ace-rs checkout)")
    parser.add_argument("--check", action="store_true",
                        help="print what the mechanical checks find in the lines the change adds, with their fixes; write no bundle")
    args = parser.parse_args()

    if args.list:
        list_repos()
        return
    if args.base and args.range:
        parser.error("--base and --range don't go together")

    ace_rs = ace_rs_checkout()
    repo = toplevel(args.repo or ace_rs)
    if args.repo and os.path.abspath(args.repo) != repo:
        sys.exit(f"{os.path.abspath(args.repo)} is not a repo's top level (it is inside {repo})")

    if args.range:
        start, _, end = args.range.partition("..")
        merge_base = git(repo, "merge-base", start, end or "HEAD").strip()
        head = git(repo, "rev-parse", end or "HEAD").strip()
        base = rules_rev = start
        include_worktree = False
        tree = git(repo, "rev-parse", f"{head}^{{tree}}").strip()
    else:
        base = rules_rev = args.base or detect_base(repo)
        if not base:
            sys.exit(f"no base branch found in {repo}; pass --base")
        merge_base = git(repo, "merge-base", base, "HEAD").strip()
        head = git(repo, "rev-parse", "HEAD").strip()
        include_worktree = True
        tree = snapshot_tree(repo)
    branch = git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()

    @functools.lru_cache(maxsize=None)
    def head_text(path: str) -> str | None:
        if not include_worktree:
            return show(repo, head, path)
        return read_file(os.path.join(repo, path))

    tree_files = git(repo, "ls-tree", "-r", "--name-only", tree).splitlines()
    packages = workspace(tree_files, head_text)
    kind = "ace-rs" if "ace-core" in packages and "ace-sdk" in packages else "site"

    # diffing against the snapshot tree takes in uncommitted and untracked work
    diff = git(repo, "diff", *DIFF_FLAGS, merge_base, tree)
    changed: list[tuple[str, str, str]] = []
    for line in git(repo, "diff", *DIFF_FLAGS, "--name-status", merge_base, tree).splitlines():
        parts = [unquote(p) for p in line.split("\t")]
        changed.append((parts[0], parts[1], parts[-1]))
    if args.check:
        sys.exit(check(repo, tree, merge_base, base, changed, diff, head_text, packages))

    state_dir = args.state_dir or os.path.join(ace_rs, "local", "ace-review")
    label = f"range-{args.range}" if args.range else (branch if branch != "HEAD" else head[:12])
    state = os.path.join(state_dir, safe_name(f"{os.path.basename(repo)}-{label}"))
    number, out, previous_dir = next_round(state)
    previous_target = load_json(os.path.join(previous_dir, "target.json"), {}) if previous_dir else {}

    write(out, "diff.patch", diff)
    write(out, "stat.txt", git(repo, "diff", *DIFF_FLAGS, "--stat", merge_base, tree))
    write(out, "log.txt", git(repo, "log", "--no-merges", "--format=--- %h %an%n%B", f"{merge_base}..{head}"))
    write(out, "files.txt", "".join(f"{status}\t{path}\n" for status, _, path in changed))

    delta, delta_reason, delta_diff, unchanged = False, None, "", False
    if previous_target:
        previous_tree = previous_target.get("tree", "")
        tree_present = bool(previous_tree) and not subprocess.run(
            ["git", "-C", repo, "cat-file", "-e", f"{previous_tree}^{{tree}}"], capture_output=True).returncode
        unchanged = previous_tree == tree or (
            previous_target.get("merge_base") == merge_base and tree_present
            and not git(repo, "diff", "--name-only", previous_tree, tree).strip())
        if args.full:
            delta_reason = "--full"
        elif previous_target.get("merge_base") != merge_base:
            delta_reason = "the merge-base moved since the last round (a rebase, or a merge from the base)"
        elif not tree_present:
            delta_reason = "the last round's tree is no longer in the object store"
        else:
            delta = True
            delta_diff = git(repo, "diff", *DIFF_FLAGS, previous_tree, tree)
            write(out, "delta.patch", delta_diff)
            write(out, "delta-files.txt", git(repo, "diff", *DIFF_FLAGS, "--name-status", previous_tree, tree))

    changed_paths = {p for _, old, new in changed for p in (old, new)}
    scope = test_scope(changed, packages)
    touches_sql = any(MIGRATION.search(p) or p.startswith(".sqlx/") for p in changed_paths) or any(
        re.search(r"\bquery(?:_as|_scalar|_file|_file_as)?!\(", line) for line in diff.splitlines()
        if line[:1] in "+-" and not line.startswith(("+++", "---")))
    touches_manifests = any(p == "Cargo.toml" or p.endswith("/Cargo.toml") for p in changed_paths)
    exec_prefix = args.exec_prefix or dev_exec(repo)
    # a range of commits that aren't checked out can't be tested where they'd run
    testable = include_worktree or head == git(repo, "rev-parse", "HEAD").strip()
    if exec_prefix and testable:
        write(out, "checks.sh", checks_script(repo, out, number, exec_prefix, scope, packages, touches_sql,
                                              touches_manifests, args.coverage))

    rule_names, rule_patch = rule_changes(repo, kind, merge_base, changed_paths, head_text)
    digest = hashlib.sha256(rule_patch.encode()).hexdigest()[:16] if rule_patch else None
    previous, rule_answers, history = build_previous(state)
    rule_status = rule_answers.get(digest, "pending") if digest else "none"
    accepted = read_rules(head_text)[1] if rule_status == "accepted" else None
    tags = pinned_tags(tree_files, head_text) if kind == "site" else []
    rules_sources = snapshot_rules(ace_rs, repo, kind, rules_rev, out, tags, accepted)
    if rule_patch:
        write(out, "rule-changes.patch", rule_patch)
    related = related_docs(repo, rules_rev, changed_paths)
    if related:
        write(out, "related-docs.txt", related)
    if previous_dir:
        write(out, "previous.json", previous)

    # in a delta round, only what changed since the last round can produce a new lead
    full_added = added_lines(diff)
    leads = find_leads(repo, tree, merge_base, base, changed, head_text, packages, diff, full_added,
                       added_lines(delta_diff) if delta else full_added)
    write(out, "leads.json", leads)

    target = {
        "repo": repo,
        "kind": kind,
        "bundle": out,
        "round": number,
        "base": base,
        "merge_base": merge_base,
        "head": head,
        "tree": tree,
        "branch": branch,
        "includes_uncommitted": include_worktree,
        "previous_round": int(os.path.basename(previous_dir).removeprefix("round-")) if previous_dir else None,
        "unchanged": unchanged,
        "delta": delta,
        "delta_reason": delta_reason,
        "history": history,
        "rules": rules_sources,
        "pinned_tags": tags,
        "rule_changes": rule_names,
        "rule_changes_digest": digest,
        "rule_changes_status": rule_status,
        "changed_files": len(changed),
        "test_scope": scope,
        "checks": ("checks.sh" if exec_prefix and testable else
                   "none: the range isn't checked out" if exec_prefix else "none: no dev service found; pass --exec"),
        "dev_exec": exec_prefix,
        "coverage": bool(args.coverage and exec_prefix and testable and (scope["packages"] or scope["workspace"])),
        "leads": len(leads),
        "touches_sql": touches_sql,
        "touches_manifests": touches_manifests,
        "touches_migrations": sorted(p for p in changed_paths if MIGRATION.search(p)),
    }
    write(out, "target.json", target)
    print(json.dumps(target, indent=2))


if __name__ == "__main__":
    main()
