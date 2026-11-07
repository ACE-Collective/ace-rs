"""Run one ace3 analysis module on one observable in the cli analysis mode and dump its analysis
as JSON (PLAN.md step 1.24).

It runs inside ace3's dev container on ace3's Python, with everything it writes under its work
directory in /tmp, never under /opt/ace (ace3's checkout):

    docker exec -i -e PYTHONDONTWRITEBYTECODE=1 ace-dev-1 /venv/bin/python3 - \\
        --work /tmp/ace4-dumps/runs/<name> --module email_analyzer --enable file_type \\
        --file /tmp/ace4-dumps/samples/ace3/email/smtp.email.rfc822 --alert-path email.rfc822 \\
        < tools/ace3/dumps/run_module.py

tools/ace3/dumps/make-dumps calls it for each module and sample. It does what `ace correlate`
does (saq/cli/commands/correlate.py) with all modules disabled except the ones named, but:

- data, temp and log files go to the work directory, not SAQ_HOME/data, and the process runs
  with the work directory as its cwd;
- the analysis cache is off, so nothing reaches ace3's database;
- with --yara-rules, the YARA module scans with its local scanner over that rule directory,
  because the yara service only knows ace3's own signatures;
- with --record-http, every request made through `requests` is written to http.json with its
  response, so a port can replay them;
- with --config, ace3 loads that YAML file over its own configuration, as `ace -c` does, which is
  how the Splunk dumps point a module at tools/ace3/dumps/fake_splunk.py for one run;
- with --replay-http, requests made through `requests` get the answers recorded in that directory
  and fail when none was, and WHOIS fails, so the run reaches nothing outside the container;
- with --tree, it also writes tree.json, the whole root in the normal form of PLAN.md 3.1
  (crates/ace-core/src/normal.rs), which tools/ace3/trees/make-trees collects.

The dump lists every analysis on the observable (the module's and its dependencies'), with the
observables each one added, and what the module did to the observable itself (tags, directives,
detections). Paths under the work directory are written relative to it.
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import uuid

ACE3 = "/opt/ace"

LOGGING_CONFIG = """\
version: 1
disable_existing_loggers: false
formatters:
  base:
    format: '[%(levelname)s] %(name)s: %(message)s'
handlers:
  console:
    class: logging.StreamHandler
    level: INFO
    formatter: base
    stream: ext://sys.stderr
loggers:
  '':
    handlers: [console]
    level: INFO
"""


def parse_args():
    parser = argparse.ArgumentParser(prog="run_module.py")
    parser.add_argument("--work", required=True, help="work directory under /tmp; replaced if it exists")
    parser.add_argument("--module", required=True, help="the analysis module to dump, by name")
    parser.add_argument("--enable", action="append", default=[], help="another module to run, such as a dependency")
    parser.add_argument("--file", help="a file to analyze")
    parser.add_argument("--alert-path", help="the file's path inside the alert")
    parser.add_argument("--meta-tag", action="append", default=[], help="a yara_meta tag for the file, name=value")
    parser.add_argument("--directive", action="append", default=[], help="a directive for the observable")
    parser.add_argument("--observable", nargs=2, metavar=("TYPE", "VALUE"), help="a non-file observable to analyze")
    parser.add_argument("--yara-rules", help="scan with the local YARA scanner over this signature directory")
    parser.add_argument("--record-http", action="store_true", help="record HTTP requests made through requests")
    parser.add_argument("--config", action="append", default=[], help="a YAML file ace3 loads over its configuration")
    parser.add_argument("--replay-http", action="append", default=[], help="a directory of recorded HTTP to answer from")
    parser.add_argument("--tree", action="store_true", help="also write the root in the normal form to tree.json")
    parser.add_argument("--label", default="", help="a name for the input, written into the dump")
    args = parser.parse_args(sys.argv[1:])
    if bool(args.file) == bool(args.observable):
        parser.error("give exactly one of --file and --observable")
    if not args.work.startswith("/tmp/"):
        parser.error("--work must be under /tmp")
    return args


class HttpRecorder:
    """Wraps requests.Session.send and keeps every request and response."""

    # bodies too big to be worth keeping, by URL prefix; their size and sha256 are still recorded
    SKIP_BODY_PREFIXES = ("https://publicsuffix.org/",)

    def __init__(self, bodies_dir):
        self.bodies_dir = bodies_dir
        self.exchanges = []

    def install(self):
        import requests

        original_send = requests.Session.send
        recorder = self

        def send(session, request, **kwargs):
            entry = {
                "method": request.method,
                "url": request.url,
                "request_headers": {k: v for k, v in request.headers.items() if k.lower() != "authorization"},
            }
            try:
                response = original_send(session, request, **kwargs)
            except Exception as e:
                entry["error"] = f"{type(e).__name__}: {e}"
                recorder.exchanges.append(entry)
                raise
            body = response.content
            entry["status"] = response.status_code
            entry["response_headers"] = dict(response.headers)
            entry["body_size"] = len(body)
            entry["body_sha256"] = hashlib.sha256(body).hexdigest()
            if not request.url.startswith(recorder.SKIP_BODY_PREFIXES):
                name = f"{len(recorder.exchanges):03d}-{entry['body_sha256'][:12]}.body"
                with open(os.path.join(recorder.bodies_dir, name), "wb") as fp:
                    fp.write(body)
                entry["body_file"] = name
            recorder.exchanges.append(entry)
            return response

        requests.Session.send = send


def replay_http(directories):
    """Answers requests from recordings HttpRecorder wrote, by method and URL, in order, so a URL
    recorded twice gives each answer once and then keeps giving the last. Nothing else goes out."""
    import io

    import requests
    import whois
    from whois.exceptions import PywhoisError

    recorded = {}
    for directory in directories:
        with open(os.path.join(directory, "http.json")) as fp:
            for exchange in json.load(fp)["exchanges"]:
                if "body_file" in exchange:
                    with open(os.path.join(directory, exchange["body_file"]), "rb") as body:
                        recorded.setdefault((exchange["method"], exchange["url"]), []).append(
                            (exchange["status"], body.read())
                        )

    def send(session, request, **kwargs):
        answers = recorded.get((request.method, request.url))
        if not answers:
            raise requests.ConnectionError(f"nothing recorded for {request.method} {request.url}")
        status, body = answers.pop(0) if len(answers) > 1 else answers[0]
        response = requests.Response()
        response.status_code = status
        response.raw = io.BytesIO(body)
        response.url = request.url
        response.request = request
        return response

    requests.Session.send = send

    def no_whois(*_args, **_kwargs):
        raise PywhoisError("no WHOIS in a replay")

    whois.whois = no_whois


# What the normal form calls each ace3 analysis, and the fields of a result that describe the run
# rather than the sample: RUN_FIELDS in crates/ace-core/src/normal.rs, by ace3's class.
TREE_MODULES = {
    "EmailAnalysis": "email_analyzer",
    "FileTypeAnalysis": "file_type",
    "ArchiveAnalysis": "archive",
    "OLEVBA_Analysis_v1_2": "olevba_v1_2",
    "MSOfficeEncryptionAnalysis": "msoffice_encryption_analyzer",
    "PCodeAnalysis": "pcodedmp",
    "RdapAnalysis": "rdap_analyzer",
    "RTFOLEObjectAnalysis": "rtfole",
    "XLMMacroDeobfuscatorAnalysis": "xlmdeobfuscator",
    "YaraScanResults_v3_4": "yara_scanner_v3_4",
    "SplunkAPIAnalysis": "clicker_detection_splunk",
}
TREE_RUN_FIELDS = {
    "EmailAnalysis": ["details/email/log_entry/date"],
    "RdapAnalysis": [
        "summary",
        "details/age_created_in_days",
        "details/age_last_updated_in_days",
        "details/datetime_of_analysis",
    ],
    "SplunkAPIAnalysis": [
        "details/end_time",
        "details/query_start",
        "details/running_start_time",
        "details/search_id",
        "details/start_time",
    ],
    "YaraScanResults_v3_4": ["details/scan_results/*/commit", "details/scan_results/*/ruleset"],
}
# ace3's excluded_analysis holds `module:<class ...>` strings
TREE_EXCLUDED = {
    "EmailAnalyzer": "email_analyzer",
    "MessageIDAnalyzerV2": "message_id_analyzer_v2",
    "ArchiveAnalyzer": "archive",
    "OLEVBA_Analyzer_v1_2": "olevba_v1_2",
    "RTFOLEObjectAnalyzer": "rtfole",
    "MSOfficeEncryptionAnalyzer": "msoffice_encryption_analyzer",
    "PCodeAnalyzer": "pcodedmp",
    "XLMMacroDeobfuscatorAnalyzer": "xlmdeobfuscator",
    "YaraScanner_v3_4": "yara_scanner_v3_4",
}


def remove_at(value, segments):
    if isinstance(value, dict) and len(segments) == 1:
        value.pop(segments[0], None)
    elif isinstance(value, dict):
        if segments[0] in value:
            remove_at(value[segments[0]], segments[1:])
    elif isinstance(value, list) and segments[0] == "*":
        for item in value:
            remove_at(item, segments[1:])


def tree_time(time):
    """As chrono's to_rfc3339_opts(AutoSi, true) writes it."""
    import datetime

    time = time.astimezone(datetime.timezone.utc)
    text = time.strftime("%Y-%m-%dT%H:%M:%S")
    if time.microsecond:
        text += f".{time.microsecond // 1000:03d}" if time.microsecond % 1000 == 0 else f".{time.microsecond:06d}"
    return text + "Z"


def rtfole_in_alert_paths(result, files_dir):
    """rtfobj's report names the file and its objects by the paths ace3 gave it, on its node, and
    ace3 lists the objects in its filesystem's order. The port writes paths in the alert and sorts
    them. So those two things, and nothing else in these fields, are put the same here, and any
    other difference in the report shows."""
    from saq.util.strings import format_item_list_for_summary

    details = result["details"]
    for field in ("stdout", "stderr"):
        if isinstance(details[field], str):
            details[field] = details[field].replace(files_dir + "/", "")
    details["extracted_files"] = sorted(path.replace(files_dir + "/", "") for path in details["extracted_files"])
    if details["extracted_files"]:
        result["summary"] = (
            "RTF OLE Object Analysis: extracted " + format_item_list_for_summary(details["extracted_files"])
        )


def msoffice_in_alert_paths(result, files_dir):
    """The candidates from the body come out of a set, in an order that changes from run to run, and
    office2john.py names the file by the path it was given, on the node. The port sorts them and
    writes the path in the alert. Those two things are put the same here."""
    details = result["details"]
    details["word_list"] = details["word_list"][:2] + sorted(details["word_list"][2:])
    for field in ("error",):
        if isinstance(details[field], str):
            details[field] = details[field].replace(files_dir + "/", "")
    if isinstance(result["summary"], str):
        result["summary"] = result["summary"].replace(files_dir + "/", "")


def xlm_output_value(observable, files_dir):
    """The sha256 of an xlmdeobfuscator output as the port writes it. ace3's holds its path on the node
    and how long the pass took, which it can't have twice, so its sha256 is new each run and a row
    could only say "some file". These two things, in the first and last lines, are put the same here,
    so any other byte that differs shows as a file on one side only."""
    import re

    with open(observable.full_path, "rb") as fp:
        stdout = fp.read()
    stdout = stdout.replace(os.fsencode(files_dir + "/"), b"")
    stdout = re.sub(rb"time elapsed: [0-9.e+-]+\n\Z", b"", stdout)
    return hashlib.sha256(stdout).hexdigest()


def tree_form(root):
    def members(items):
        return {item: True for item in items}

    observables = {}
    # ace3's own order changes from run to run, and two observables can merge below
    for observable in sorted(root.all_observables, key=lambda o: o.file_path if o.type == "file" else ""):
        entry = {
            "tags": members(str(tag) for tag in observable.tags),
            "directives": members(d for d in observable.directives if not d.startswith("yara_meta:")),
            "excluded_analysis": members(
                TREE_EXCLUDED.get(class_name, class_name)
                for class_name in (
                    excluded.rsplit(".", 1)[-1].removesuffix("'>") for excluded in observable.excluded_analysis
                )
            ),
            "relationships": members(
                f"{r.r_type} {r.target.type}:{r.target.value}" for r in observable.relationships
            ),
            "detections": {},
            "results": {},
        }
        detections = list(observable.detections)
        for analysis in observable.all_analysis:
            analysis.load_details()
            class_name = type(analysis).__name__
            detections.extend(analysis.detections)
            result = {
                "summary": analysis.summary,
                "tags": members(str(tag) for tag in analysis.tags),
                "details": json_safe(analysis.details),
            }
            for path in TREE_RUN_FIELDS.get(class_name, []):
                remove_at(result, path.split("/"))
            # ace3 writes this with json.dumps' spaces and ace4 with serde_json, so it's compared
            # as the same compact text, which any change to its content still shows
            raw = result["details"].get("rdap_raw_json") if class_name == "RdapAnalysis" else None
            if isinstance(raw, str):
                result["details"]["rdap_raw_json"] = json.dumps(json.loads(raw), separators=(",", ":"), ensure_ascii=False)
            if class_name == "RTFOLEObjectAnalysis":
                rtfole_in_alert_paths(result, observable.full_path.removesuffix("/" + observable.file_path))
            if class_name == "MSOfficeEncryptionAnalysis":
                msoffice_in_alert_paths(result, observable.full_path.removesuffix("/" + observable.file_path))
            entry["results"][TREE_MODULES.get(class_name, class_name)] = result
        for detection in detections:
            entry["detections"].setdefault(detection.description, []).append(json_safe(detection.details))
        for details in entry["detections"].values():
            details.sort(key=lambda d: json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
        if observable.time is not None:
            entry["time"] = tree_time(observable.time)
        if observable.redirection is not None:
            entry["redirection"] = f"{observable.redirection.type}:{observable.redirection.value}"
        if observable.type == "file":
            entry["paths"] = {observable.file_path: members(sorted(observable.yara_meta_tags))}
        value = observable.value
        if observable.type == "file" and os.path.dirname(observable.file_path).endswith(".xlmdeobfuscator"):
            if observable.file_name in ("xlmdeobfuscator.stdout", "xlmdeobfuscatorextractcells.stdout"):
                value = xlm_output_value(observable, observable.full_path.removesuffix("/" + observable.file_path))
        key = f"{observable.type}:{value}"
        if key in observables:
            merge_tree_entry(observables[key], entry)
        else:
            observables[key] = entry
    return {"form": 1, "observables": observables}


def merge_tree_entry(entry, later):
    """The form has one entry per (type, value), and ace3 has an observable per sha256 and path
    (FileObservable.__eq__), each analyzed on its own. So an entry gets every path and the union
    of what its observables hold. A module's result is that of the path that sorts first, because
    the form has one per module and ace3's two can differ, by the names they derive from their
    path."""
    for field in ("tags", "directives", "excluded_analysis", "relationships"):
        entry[field].update(later[field])
    for path, tags in later.get("paths", {}).items():
        entry["paths"].setdefault(path, {}).update(tags)
    for description, details in later["detections"].items():
        known = entry["detections"].setdefault(description, [])
        known.extend(d for d in details if d not in known)
        known.sort(key=lambda d: json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
    for module, result in later["results"].items():
        entry["results"].setdefault(module, result)
    for field in ("time", "redirection"):
        if field in later:
            entry.setdefault(field, later[field])


def prepare_work_dir(work):
    if os.path.exists(work):
        shutil.rmtree(work)
    for sub in ("data", "tmp", "home", "http", "bin"):
        os.makedirs(os.path.join(work, sub))
    # ArchiveAnalyzer runs bin/unjar relative to the cwd, which ace3 expects to be SAQ_HOME
    os.symlink(os.path.join(ACE3, "bin", "unjar"), os.path.join(work, "bin", "unjar"))
    with open(os.path.join(work, "logging.yaml"), "w") as fp:
        fp.write(LOGGING_CONFIG)
    os.environ["HOME"] = os.path.join(work, "home")
    os.environ["TLDEXTRACT_CACHE"] = os.path.join(work, "home", "tldextract")
    os.chdir(work)


def json_safe(value):
    """Round-trips a value through ace3's own JSON encoder, the way ace3 stores details. A lone
    surrogate from a hostile file's name stays visible as its escape, as text: a tree is UTF-8, and
    JSON readers refuse it as `\\ud800`."""
    from saq.json_encoding import _JSONEncoder

    def visible(item):
        if isinstance(item, str):
            return item.encode("utf-8", "backslashreplace").decode("utf-8")
        if isinstance(item, list):
            return [visible(i) for i in item]
        if isinstance(item, dict):
            return {visible(k): visible(v) for k, v in item.items()}
        return item

    return visible(json.loads(json.dumps(value, cls=_JSONEncoder)))


def dump_observable(observable):
    entry = {"type": observable.type, "value": observable.value}
    if observable.type == "file":
        entry["file_path"] = observable.file_path
        entry["size"] = observable.size
        entry["yara_meta"] = sorted(observable.yara_meta_tags)
    if observable.time is not None:
        entry["time"] = str(observable.time)
    entry["directives"] = sorted(observable.directives)
    # set by an observable mapping's display_type, such as the Splunk module's; ace3 stores it
    if getattr(observable, "_display_type", None) is not None:
        entry["display_type"] = observable._display_type
    entry["tags"] = sorted(str(tag) for tag in observable.tags)
    entry["detections"] = [
        {"description": d.description, "details": json_safe(d.details)} for d in observable.detections
    ]
    entry["relationships"] = [
        {"type": r.r_type, "target": {"type": r.target.type, "value": r.target.value}}
        for r in observable.relationships
    ]
    if observable.redirection is not None:
        entry["redirection"] = {"type": observable.redirection.type, "value": observable.redirection.value}
    entry["excluded_analysis"] = sorted(observable.excluded_analysis)
    return entry


def dump_analysis(analysis):
    analysis.load_details()
    return {
        "module_path": analysis.module_path,
        "class": type(analysis).__name__,
        "summary": analysis.summary,
        "details": json_safe(analysis.details),
        "tags": sorted(str(tag) for tag in analysis.tags),
        "detections": [
            {"description": d.description, "details": json_safe(d.details)} for d in analysis.detections
        ],
        "observables": [dump_observable(o) for o in analysis.observables],
    }


def relative_paths(value, prefixes):
    """Replaces the work directory and storage paths in every string with a placeholder."""
    if isinstance(value, dict):
        return {k: relative_paths(v, prefixes) for k, v in value.items()}
    if isinstance(value, list):
        return [relative_paths(v, prefixes) for v in value]
    if isinstance(value, str):
        for prefix, placeholder in prefixes:
            value = value.replace(prefix, placeholder)
        return value
    return value


def main():
    args = parse_args()
    work = os.path.abspath(args.work)
    prepare_work_dir(work)
    sys.path.insert(0, ACE3)

    recorder = None
    if args.replay_http:
        replay_http(args.replay_http)
    if args.record_http:
        recorder = HttpRecorder(os.path.join(work, "http"))
        recorder.install()

    from saq.environment import initialize_environment

    initialize_environment(
        saq_home=ACE3,
        data_dir=os.path.join(work, "data"),
        temp_dir=os.path.join(work, "tmp"),
        config_paths=args.config,
        logging_config_path=os.path.join(work, "logging.yaml"),
    )

    import datetime
    import socket

    from saq.analysis import RootAnalysis
    from saq.configuration import get_config
    from saq.configuration.config import get_analysis_module_config, get_service_config
    from saq.constants import ANALYSIS_MODE_CLI, SERVICE_YARA_SCANNER, EventTimeSource
    from saq.engine.core import Engine
    from saq.engine.engine_configuration import EngineConfiguration
    from saq.engine.enums import EngineExecutionMode, EngineType

    # results must not reach ace3's database through the analysis cache
    get_config().analysis_cache.enabled = False

    if args.yara_rules:
        from saq.yara_scanning import client as yara_client
        from saq.yara_scanning.client import YaraServiceUnavailable

        rules = os.path.join(work, "signatures")
        shutil.copytree(args.yara_rules, rules)
        yara_config = get_service_config(SERVICE_YARA_SCANNER)
        yara_config.signature_dir = rules
        yara_config.git_repo_dirs = []

        def service_unavailable(*_args, **_kwargs):
            raise YaraServiceUnavailable("run_module.py scans with the local scanner")

        yara_client.scan_file = service_unavailable

    root_dir = os.path.join(work, "root")
    root = RootAnalysis(uuid=str(uuid.uuid4()), storage_dir=root_dir)
    root.initialize_storage()
    root.tool = "ACE - Command Line Analysis"
    root.tool_instance = socket.gethostname()
    root.alert_type = "cli_analysis"
    root.analysis_mode = ANALYSIS_MODE_CLI
    get_config().get_analysis_mode_config(root.analysis_mode).cleanup = False
    root.description = "ace4 reference dump"
    root.set_event_time(datetime.datetime.now(), EventTimeSource.NOW)
    root.details = {"comment": "ace4 reference dump"}

    if args.file:
        observable = root.add_file_observable(args.file, target_path=args.alert_path)
        for tag in args.meta_tag:
            name, value = tag.split("=", 1)
            observable.add_yara_meta(name, value)
    else:
        observable = root.add_observable_by_spec(args.observable[0], args.observable[1])
    if observable is None:
        sys.exit("ace3 refused the observable")
    for directive in args.directive:
        observable.add_directive(directive)
    target_uuid = observable.uuid
    root.save()

    engine = Engine(config=EngineConfiguration(engine_type=EngineType.LOCAL, single_threaded_mode=True))
    engine.configuration_manager.config.alerting_enabled = False
    worker = engine.initialize_single_threaded_worker()
    worker.workload_manager.add_workload(root)

    for module_config in get_config().analysis_modules:
        module_config.enabled = False
    for name in [args.module, *args.enable]:
        get_analysis_module_config(name).enabled = True
        engine.configuration_manager.enable_module(name, ANALYSIS_MODE_CLI)

    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = RootAnalysis(storage_dir=root_dir)
    root.load()
    target = root.get_observable(target_uuid)

    commit = subprocess.run(
        ["git", "-C", ACE3, "rev-parse", "--short=8", "HEAD"], capture_output=True, text=True, check=False
    ).stdout.strip()

    dump = {
        "about": "One ace3 module's analysis of one observable in the cli analysis mode, "
        "written by tools/ace3/dumps/run_module.py.",
        "ace3_commit": commit or None,
        "module": args.module,
        "also_enabled": args.enable,
        "input": {
            "label": args.label,
            "observable": {"type": target.type, "value": target.value}
            | ({"file_path": target.file_path, "size": target.size} if target.type == "file" else {}),
            "meta_tags": args.meta_tag,
            "directives": args.directive,
        },
        "observable_after": dump_observable(target),
        "analyses": [dump_analysis(a) for a in target.all_analysis],
    }
    if args.tree:
        tree = relative_paths(tree_form(root), [(root_dir, "<root>"), (work, "<work>")])
        with open(os.path.join(work, "tree.json"), "w") as fp:
            json.dump(tree, fp, indent=2, sort_keys=True, ensure_ascii=False)
            fp.write("\n")
    if recorder is not None:
        dump["http_exchanges"] = len(recorder.exchanges)
        recording = {
            "about": "Every request the module made through requests, in order, with its response. "
            "Each body_file holds the body after requests undid any Content-Encoding, so a replay "
            "serves it without that header. Bodies too large to keep have only body_size and "
            "body_sha256.",
            "exchanges": recorder.exchanges,
        }
        with open(os.path.join(work, "http", "http.json"), "w") as fp:
            json.dump(recording, fp, indent=2, sort_keys=True)

    dump = relative_paths(dump, [(root_dir, "<root>"), (work, "<work>")])
    with open(os.path.join(work, "dump.json"), "w") as fp:
        json.dump(dump, fp, indent=2, sort_keys=True, ensure_ascii=False)
        fp.write("\n")
    logging.info("wrote %s", os.path.join(work, "dump.json"))


if __name__ == "__main__":
    main()
