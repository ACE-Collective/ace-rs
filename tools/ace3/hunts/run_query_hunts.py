"""Run ace3's Splunk hunter over hunts written for the comparison, against fake_splunk.py, and write
what it would submit (PLAN.md step 6.4).

It runs inside ace3's dev container on ace3's Python, writing only under its work directory in /tmp:

    docker exec -i -e PYTHONDONTWRITEBYTECODE=1 -e SAQ_SKIP_LOCAL_SAQ_YAML=1 ace-dev-1 \\
        /venv/bin/python3 - --work /tmp/ace4-dumps/query/work --cases /tmp/ace4-dumps/query/cases \\
        --fake /tmp/ace4-dumps/query/fake_splunk.py < tools/ace3/hunts/run_query_hunts.py

tools/ace3/hunts/make-query-hunts calls it. Each hunt in the cases' hunts/ is loaded as ace3's
HuntManager loads a Splunk hunt (SplunkHunt with the manager), and runs.yaml lists its ticks: the
time ace3's clock reads, and the rows the fake answers that tick's search with. A tick does what
HuntManager.execute does for the one hunt: it skips a hunt that's disabled, for another instance
type, suppressed or not ready, and otherwise runs HuntManager.execute_threaded_hunt, the hunter's own path from executing
the hunt to staging its submissions. The file manager that would stage them (to be sent to ace3's
database by the collector) is replaced by one that records each submission's normal form, so
nothing reaches ace3's database. The hunt's persisted state (last end, executed and alert times)
lives under the work directory, as ace3 keeps it under its data directory.

Each tick starts the fake afresh with that tick's rows (--any-hostname: every search gets them),
records every exchange, and the tick's entry in the output holds the exchanges, the submissions
and the hunt's state after it.

The correlated cases (PLAN.md step 6.6) run ace3's correlation engine in the same run, its queries
going to the same fake through ace3's SplunkQuerySource on the `default` instance, with no secrets
to scrub and no cache, so nothing reaches ace3's database or Redis.

It also records each suppression decision (PLAN.md step 6.5). A grouped hunt's are what
QueryHunt.process_query_results hands record_suppressed, which is replaced by a recorder, so
nothing reaches ace3's SVS tables: each dropped submission's group value, description, event time,
and the window its group's last alert time opened. A duplicate is what ace3's collector would do with
the staged submissions: each goes through ace3's own DuplicateSubmissionFilter, in order, with the
hunter service's persistence settings, over a store that keeps the keys in memory rather than in
ace3's persistence table and expires them as Persistable.delete_expired_persistent_keys does, at the
tick's clock rather than the database's. The collector clears expired keys every
persistence_clear_seconds (60), and the ticks are minutes apart, so each tick clears first. Times and the clock are fixed, so a run gives the same output each
time but for ace3's root uuids, which aren't written.
"""

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import threading
import time

ACE3 = "/opt/ace"

# The Splunk instances the cases name: `default` in GMT and `eastern` in New York, both the fake.
SPLUNK_CONFIG = """\
splunk_config_default:
  name: default
  enabled: true
  host: 127.0.0.1
  port: 8089
  username: ace4
  password: ace4-fake-password
  timezone: GMT
  performance_logging_dir: ""
  request_timeout: 10
splunk_config_eastern:
  name: eastern
  enabled: true
  host: 127.0.0.1
  port: 8089
  username: ace4
  password: ace4-fake-password
  timezone: America/New_York
  performance_logging_dir: ""
  request_timeout: 10
"""

LOGGING_CONFIG = """\
version: 1
disable_existing_loggers: false
handlers:
  console:
    class: logging.StreamHandler
    level: CRITICAL
    stream: ext://sys.stderr
loggers:
  '':
    handlers: [console]
    level: CRITICAL
"""


class Clock:
    """ace3's local_time(), fixed at the tick's time."""

    def __init__(self):
        self.now = None

    def __call__(self):
        return self.now


CLOCK = Clock()


def parse_args():
    parser = argparse.ArgumentParser(prog="run_query_hunts.py")
    parser.add_argument("--work", required=True, help="work directory under /tmp; replaced if it exists")
    parser.add_argument("--cases", required=True, help="the directory with hunts/ and runs.yaml")
    parser.add_argument("--fake", required=True, help="fake_splunk.py")
    args = parser.parse_args(sys.argv[1:])
    if not args.work.startswith("/tmp/"):
        parser.error("--work must be under /tmp")
    return args


def setup(work, cases):
    if os.path.exists(work):
        shutil.rmtree(work)
    for sub in ("data", "tmp", "home", "staging", "fake"):
        os.makedirs(os.path.join(work, sub))
    with open(os.path.join(work, "logging.yaml"), "w") as fp:
        fp.write(LOGGING_CONFIG)
    with open(os.path.join(work, "saq.splunk.yaml"), "w") as fp:
        fp.write(SPLUNK_CONFIG)
    # the hunts name their query files under $QUERIES, which is where the copy puts them
    hunts = os.path.join(work, "hunts")
    shutil.copytree(os.path.join(cases, "hunts"), hunts)
    for directory, _, names in os.walk(hunts):
        for name in names:
            if name.endswith(".yaml"):
                path = os.path.join(directory, name)
                with open(path) as fp:
                    text = fp.read()
                with open(path, "w") as fp:
                    fp.write(text.replace("$QUERIES", os.path.join(hunts, "queries")))
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", os.path.join(work, "fake", "key.pem"),
         "-out", os.path.join(work, "fake", "cert.pem")],
        check=True, capture_output=True)
    os.environ["HOME"] = os.path.join(work, "home")
    os.chdir(work)
    sys.path.insert(0, ACE3)

    from saq.environment import initialize_environment

    initialize_environment(
        saq_home=ACE3,
        data_dir=os.path.join(work, "data"),
        temp_dir=os.path.join(work, "tmp"),
        config_paths=[os.path.join(work, "saq.splunk.yaml")],
        logging_config_path=os.path.join(work, "logging.yaml"),
    )

    # every local_time() the hunter, the Splunk client and the analysis read is the tick's
    import saq.analysis.root
    import saq.collectors.hunter.base_hunter
    import saq.collectors.hunter.query_hunter
    import saq.splunk
    import saq.util
    import saq.util.time

    for module in (saq.collectors.hunter.base_hunter, saq.collectors.hunter.query_hunter, saq.splunk,
                   saq.util, saq.util.time, saq.analysis.root):
        if hasattr(module, "local_time"):
            module.local_time = CLOCK

    # correlation (step 6.6): the query sources the hunter registers at startup, ace3's `splunk` on
    # the `default` instance; its secrets and its cache are ace3's database and Redis, which nothing
    # here reaches, so the secrets are none and a cache lookup fails the run
    import saq.collectors.hunter.correlation.commands
    import saq.collectors.hunter.correlation.engine
    from saq.collectors.hunter.correlation.sources import load_query_sources_from_config

    load_query_sources_from_config(force=True)
    saq.collectors.hunter.correlation.engine.export_encrypted_passwords = lambda: {}

    def no_cache(*args, **kwargs):
        raise SystemExit("a case's correlation reached ace3's cache")

    saq.collectors.hunter.correlation.commands.get_cached_result = no_cache
    saq.collectors.hunter.correlation.commands.set_cached_result = no_cache
    return hunts


def iso(value):
    if value is None:
        return None
    return value.astimezone(datetime.timezone.utc).isoformat()


def jsonable(value):
    # as ace3 saves a root's details: a datetime in EVENT_TIME_FORMAT_JSON_TZ (a correlation trace's
    # query window), anything else it can't write as its str()
    from saq.json_encoding import _JSONEncoder

    class Encoder(_JSONEncoder):
        def default(self, obj):
            try:
                return super().default(obj)
            except TypeError:
                return str(obj)

    return json.loads(json.dumps(value, cls=Encoder, sort_keys=True))


def observable_normal(observable):
    return {
        "type": observable.type,
        "value": observable.value,
        "time": iso(observable.time) if isinstance(observable.time, datetime.datetime) else observable.time,
        "tags": [str(tag) for tag in observable.tags],
        "directives": list(observable.directives),
        "display_type": observable._display_type if hasattr(observable, "_display_type") else None,
        "display_value": observable._display_value if hasattr(observable, "_display_value") else None,
        "volatile": observable.volatile,
        "relationships": [
            {"type": r.r_type, "target": {"type": r.target.type, "value": r.target.value}}
            for r in observable.relationships
        ],
    }


def submission_normal(submission):
    """What a staged submission says, every field ace3's root and submission carry but its uuid and
    storage directory."""
    root = submission.root
    return {
        "key": submission.key,
        "group_value": getattr(submission, "group_value", None),
        "suppression_key": getattr(submission, "suppression_key", None),
        "description": root.description,
        "instructions": root.instructions,
        "analysis_mode": root.analysis_mode,
        "alert_type": root.alert_type,
        "queue": root.queue,
        "tool": root.tool,
        "tool_instance": root.tool_instance,
        "event_time": iso(root.event_time),
        "event_time_source": str(root.event_time_source),
        "details": jsonable(root.details),
        "extensions": jsonable(root.extensions),
        "tags": [str(tag) for tag in root.tags],
        "pivot_links": [{"url": p.url, "icon": p.icon, "text": p.text} for p in root.pivot_links],
        "summary_details": [{"header": d.header, "content": d.content, "format": d.format}
                            for d in root.summary_details],
        "detections": [
            {"description": d.description, "signature_uuid": d.signature_uuid,
             "signature_version": d.signature_version, "signature_family": d.signature_family}
            for d in root.detections
        ],
        "observables": [observable_normal(o) for o in root.observables],
    }


class CapturingFileManager:
    """Stands in for the SubmissionFileManager the manager stages submissions with."""

    def __init__(self, staging):
        self.staging = staging
        self.staged = []
        self.keys = []

    def get_staging_tmp_dir(self):
        return self.staging

    def stage_submission(self, submission):
        self.staged.append(submission_normal(submission))
        self.keys.append(submission.key)
        return self.staging

    def list_staged_submissions(self):
        return []


class ClockPersistence:
    """The persistence the collector's DuplicateSubmissionFilter keeps its keys in, in memory: a key's
    created_at and last_update, at the tick's clock."""

    persistence_source = "hunter"

    def __init__(self):
        self.keys = {}

    def persistent_data_exists(self, key_name):
        return truncate(key_name) in self.keys

    def save_persistent_key(self, key_name):
        # save_persistent_data's INSERT ... ON DUPLICATE KEY UPDATE last_update
        key_name = truncate(key_name)
        created = self.keys.get(key_name, (CLOCK.now, None))[0]
        self.keys[key_name] = (created, CLOCK.now)

    def delete_expired_persistent_keys(self, expiration_timedelta, unmodified_expiration_timedelta):
        # its two deletes, by created_at and by last_update
        expiration_date = CLOCK.now - expiration_timedelta
        unmodified_expiration_date = CLOCK.now - unmodified_expiration_timedelta
        self.keys = {k: (created, updated) for k, (created, updated) in self.keys.items()
                     if not created < expiration_date and not updated < unmodified_expiration_date}


def truncate(key_name):
    from saq.persistence import truncate_key

    return truncate_key(key_name)


SUPPRESSED = []


def record_suppressed(hunt, suppressed):
    """Stands in for QueryHunt.record_suppressed: what the hunt dropped, and the window of each."""
    for root, group_value in suppressed:
        since = hunt.last_alert_times.get(group_value)
        SUPPRESSED.append({
            "group_value": group_value,
            "description": root.description,
            "event_time": iso(root.event_time),
            "window_start": iso(since),
            "window_end": iso(since + hunt.suppression) if since is not None else None,
        })


def start_fake(fake, work, tick_dir, rows, running_polls):
    os.makedirs(os.path.join(tick_dir, "http"))
    rows_path = os.path.join(tick_dir, "rows.json")
    with open(rows_path, "w") as fp:
        json.dump({"searches": [{"hostname": "-", "rows": rows}]}, fp)
    pid = os.path.join(tick_dir, "pid")
    process = subprocess.Popen(
        ["/venv/bin/python3", "-I", fake, "--rows", rows_path, "--cert", os.path.join(work, "fake", "cert.pem"),
         "--key", os.path.join(work, "fake", "key.pem"), "--port", "8089", "--record", os.path.join(tick_dir, "http"),
         "--pid-file", pid, "--any-hostname", "--running-polls", str(running_polls)],
        stderr=open(os.path.join(tick_dir, "fake.log"), "w"))
    for _ in range(100):
        if os.path.exists(pid):
            return process
        time.sleep(0.1)
    raise SystemExit(f"fake_splunk.py did not start: {open(os.path.join(tick_dir, 'fake.log')).read()}")


def exchanges(tick_dir):
    path = os.path.join(tick_dir, "http", "http.json")
    if not os.path.exists(path):
        return []
    with open(path) as fp:
        recorded = json.load(fp)["exchanges"]
    out = []
    for exchange in recorded:
        with open(os.path.join(tick_dir, "http", exchange["body_file"]), "rb") as fp:
            body = fp.read().decode("utf-8")
        out.append({
            "method": exchange["method"],
            "url": exchange["url"],
            "request_body": exchange["request_body"],
            "status": exchange["status"],
            "content_type": exchange["response_headers"].get("Content-Type"),
            "body": body,
        })
    return out


def state(hunt):
    return {
        "last_executed_time": iso(hunt.last_executed_time),
        "last_end_time": iso(hunt.last_end_time),
        "last_alert_time": iso(hunt.last_alert_time),
        "last_alert_times": {k: iso(v) for k, v in sorted(hunt.last_alert_times.items(), key=lambda kv: str(kv[0]))},
    }


def main():
    args = parse_args()
    work = os.path.abspath(args.work)
    import yaml

    with open(os.path.join(args.cases, "runs.yaml")) as fp:
        runs = yaml.safe_load(fp)
    hunts_dir = setup(work, os.path.abspath(args.cases))

    from saq.collectors.duplicate_filter import DuplicateSubmissionFilter
    from saq.collectors.hunter.manager import HuntManager
    from saq.collectors.hunter.query_hunter import QueryHunt
    from saq.collectors.hunter.splunk_hunter import SplunkHunt
    from saq.configuration.config import get_service_config
    from saq.constants import SERVICE_HUNTER, ExecutionMode

    QueryHunt.record_suppressed = record_suppressed
    service_config = get_service_config(SERVICE_HUNTER)

    output = {}
    for name in sorted(runs):
        file_manager = CapturingFileManager(os.path.join(work, "staging"))
        manager = HuntManager.__new__(HuntManager)
        manager.hunt_type = "splunk"
        manager.execution_mode = ExecutionMode.SINGLE_SHOT
        manager.file_manager = file_manager
        manager.wait_control_event = threading.Event()
        hunt = SplunkHunt(manager=manager, hunt_config_file_path=os.path.join(hunts_dir, name))
        hunt.semaphore = None
        persistence = ClockPersistence()
        duplicate_filter = DuplicateSubmissionFilter(persistence, service_config)
        ticks = []
        for index, tick in enumerate(runs[name]):
            CLOCK.now = datetime.datetime.fromisoformat(tick["now"])
            entry = {"now": tick["now"]}
            # HuntManager.execute, for this hunt
            if not hunt.enabled:
                entry["skipped"] = "disabled"
            elif not manager.is_valid_instance_type(hunt):
                entry["skipped"] = "invalid instance type"
            elif hunt.suppressed:
                entry["skipped"] = "suppressed"
            elif not hunt.ready:
                entry["skipped"] = "not ready"
            else:
                tick_dir = os.path.join(work, "ticks", name, str(index))
                process = start_fake(args.fake, work, tick_dir, tick["rows"], tick.get("running_polls", 0))
                try:
                    file_manager.staged = []
                    file_manager.keys = []
                    SUPPRESSED.clear()
                    manager.execute_threaded_hunt(hunt)
                finally:
                    process.terminate()
                    process.wait()
                entry["exchanges"] = exchanges(tick_dir)
                entry["submissions"] = file_manager.staged
                entry["suppressed"] = list(SUPPRESSED)
                # Collector.process_submission and clear_expired_persistent_data, for what was staged
                persistence.delete_expired_persistent_keys(
                    datetime.timedelta(seconds=service_config.persistence_expiration_seconds),
                    datetime.timedelta(seconds=service_config.persistence_unmodified_expiration_seconds))
                entry["duplicates"] = []
                for index, key in enumerate(file_manager.keys):
                    if key:
                        if duplicate_filter.is_duplicate(key):
                            entry["duplicates"].append(index)
                        else:
                            duplicate_filter.mark_as_processed(key)
            entry["state"] = state(hunt)
            ticks.append(entry)
        output[name] = ticks

    def commit(directory):
        return subprocess.run(["git", "-C", directory, "rev-parse", "HEAD"], capture_output=True,
                              text=True).stdout.strip() or None

    from saq.configuration.config import get_config

    result = {"ace3_commit": commit(ACE3), "instance_type": get_config().global_settings.instance_type,
              "work": work, "cases": output}
    text = json.dumps(result, indent=1, sort_keys=True, ensure_ascii=False).replace(work, "$WORK")
    with open(os.path.join(work, "submissions.json"), "w") as fp:
        fp.write(text + "\n")


if __name__ == "__main__":
    main()
