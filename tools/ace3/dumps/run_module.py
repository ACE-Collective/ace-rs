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
  how the Splunk dumps point a module at tools/ace3/dumps/fake_splunk.py for one run.

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
    """Round-trips a value through ace3's own JSON encoder, the way ace3 stores details."""
    from saq.json_encoding import _JSONEncoder

    return json.loads(json.dumps(value, cls=_JSONEncoder))


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
