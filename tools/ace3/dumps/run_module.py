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
- with --dns HOST:PORT, ace3's DNS resolver asks only that server, such as
  tools/ace3/dumps/fake_dns.py, instead of the container's;
- with --snort-rules PATH, ace3's snort module reads an index of that rules file, built as
  `ace signatures build-db` builds it, from a dict in place of Redis, so nothing reaches
  ace3's Redis;
- with --brocess FILE, ace3's conversation frequency module counts from the smtplog rows in that
  JSON file, summed as its SQL sums them, instead of querying brocess;
- with --brocess-store FILE, ace3's email logger and thread modules read and write a brocess held
  in memory (FakeBrocess below), which starts with the rows in that JSON file, and the dump keeps
  the rows before and after the run and what each read answered;
- with --fluent-bit, what ace3 sends to fluent-bit is kept in the dump instead of sent;
- with --encryption-key HEX, ace3's encryption is initialized with that 32-byte key, as its own
  password would load one, so its archive modules seal and open with it;
- with --email-archive-store FILE, ace3's email archive (saq/email_archive/local.py) writes and reads
  an email-archive database held in memory (FakeEmailArchive below), and its files under the work
  directory, starting with the emails that JSON file lists, each archived with ace3's own
  archive_email and the URLs it names indexed; the dump keeps the rows after the run and what each
  query answered;
- with --sidecars SUFFIX, the dump keeps the text of each file the run left in the root's file
  directory whose name ends in SUFFIX, by its path there, such as the DOM snapshots ace3's HTML
  modules write beside the scripts they extract, which aren't observables;
- with --extracted-from FILE ALERT_PATH, the root also holds that file, the observable is
  extracted_from it, and --source-tag tags it, as a document file_type called microsoft_office;
- with --added-by MODULE:CLASS, the observable is added by an analysis of that class on the
  --extracted-from file rather than by the root, such as an output of OfficeParserAnalysis3;
- with --tag TAG, the observable carries that tag, as the module that added it would give it, such as
  rtfole's extracted_rtf; the dump's input lists it;
- with --dump-file ALERT_PATH, the dump is of the file the run added under that path, such as the image
  dmg_analyzer writes, when it added one;
- with --scanner-output DIR, the scanner clients of the JavaScript deobfuscator and phishkit
  (saq/js_deobfuscator.py, saq/phishkit.py) don't send a Celery task: each gives back a copy of DIR,
  a scan's output directory as the manager leaves it (tools/ace3/dumps/scanner-fixtures), and the dump
  keeps what the module asked for (`scanner_request`). A URL scan whose scanner failed and left
  nothing to harvest raises as phishkit.py's scan_url does. DIR `raise:<message>` raises <message>
  instead, as a Celery call that failed does;
- with --analysis-mode MODE, the root is in that mode rather than cli, such as correlation, the only
  one phishkit renders files in;
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
import re
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
    parser.add_argument("--tag", action="append", default=[], help="a tag for the observable, as a module that added it gives")
    parser.add_argument("--observable", nargs=2, metavar=("TYPE", "VALUE"), help="a non-file observable to analyze")
    parser.add_argument(
        "--relationship", nargs=3, action="append", default=[], metavar=("KIND", "TYPE", "VALUE"),
        help="a relationship of the observable to another the root also holds, such as executed_on hostname H",
    )
    parser.add_argument(
        "--extracted-from", nargs=2, metavar=("FILE", "ALERT_PATH"),
        help="a file the root also holds, which the observable is extracted_from",
    )
    parser.add_argument("--source-tag", action="append", default=[], help="a tag for the --extracted-from file")
    parser.add_argument(
        "--added-by", metavar="MODULE:CLASS",
        help="the observable is added by an analysis of this class on the --extracted-from file",
    )
    parser.add_argument("--yara-rules", help="scan with the local YARA scanner over this signature directory")
    parser.add_argument("--record-http", action="store_true", help="record HTTP requests made through requests")
    parser.add_argument("--config", action="append", default=[], help="a YAML file ace3 loads over its configuration")
    parser.add_argument("--replay-http", action="append", default=[], help="a directory of recorded HTTP to answer from")
    parser.add_argument("--dns", metavar="HOST:PORT", help="the one DNS server ace3's resolver asks")
    parser.add_argument("--snort-rules", help="a rules file the snort module's index is built from, in memory")
    parser.add_argument("--brocess", help="a JSON file of smtplog rows the frequency module counts from")
    parser.add_argument("--brocess-store", help="a JSON file of brocess rows the email modules read and write")
    parser.add_argument("--fluent-bit", action="store_true", help="keep what ace3 sends to fluent-bit in the dump")
    parser.add_argument("--encryption-key", help="the 32-byte key, in hex, ace3's encryption is initialized with")
    parser.add_argument("--email-archive-store", help="a JSON file of emails ace3's email archive starts with")
    parser.add_argument(
        "--observable-tags", help="a JSON file of the tags ace3's database maps to observables, which "
        "user_defined_tagging reads",
    )
    parser.add_argument(
        "--detections", help="a JSON file of the observables enabled for detection, the Redis cache "
        "observable_detection reads",
    )
    parser.add_argument(
        "--export-detections", action="store_true",
        help="with --detections and --yara-rules: also export the detections to YARA rules as ace3's "
        "export-observables cron does, into the rule directory's observable_export, each detection's id "
        "its place in the file from 1, and answer the YARA module's read of a matched detection's row",
    )
    parser.add_argument("--tree", action="store_true", help="also write the root in the normal form to tree.json")
    parser.add_argument(
        "--tree-view", action="store_true",
        help="also keep the whole root in the dump, as ace4's core hands a module that walks it its tree",
    )
    parser.add_argument("--alert-type", default="cli_analysis", help="the root's alert type, such as mailbox")
    parser.add_argument(
        "--sidecars", metavar="SUFFIX",
        help="keep the text of each file the run wrote under the root whose name ends in SUFFIX, such as .dom.json",
    )
    parser.add_argument(
        "--carrying-email", metavar="BODY",
        help="the file comes as the attachment of an email, made here, whose text body is the file BODY, "
        "or whose body is the HTML file BODY when it ends in .html, or which has a text part and an HTML "
        "alternative when it ends in .both, split at a line --html--, or which has no body when BODY is -. "
        "The email is the root's file, email_analyzer has to be enabled, and the dump is the attachment's",
    )
    parser.add_argument(
        "--dump-file", metavar="ALERT_PATH",
        help="the dump is of the file the run added under ALERT_PATH, such as the image dmg_analyzer writes "
        "for a DMG, when the run added one; otherwise of the observable given",
    )
    parser.add_argument(
        "--scanner-output", metavar="DIR",
        help="answer the scanner clients with a copy of DIR, a scan's output directory, or raise:<message>",
    )
    parser.add_argument("--analysis-mode", default="cli", help="the root's analysis mode")
    parser.add_argument("--label", default="", help="a name for the input, written into the dump")
    args = parser.parse_args(sys.argv[1:])
    if bool(args.file) == bool(args.observable):
        parser.error("give exactly one of --file and --observable")
    if args.added_by and not args.extracted_from:
        parser.error("--added-by needs --extracted-from")
    if args.carrying_email and (not args.file or args.extracted_from or "email_analyzer" not in args.enable):
        parser.error("--carrying-email needs --file and --enable email_analyzer, and no --extracted-from")
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
                        # only a redirect's Location comes back: the body is stored decoded, so a
                        # Content-Encoding would be wrong
                        location = {
                            k: v for k, v in exchange.get("response_headers", {}).items() if k.lower() == "location"
                        }
                        recorded.setdefault((exchange["method"], exchange["url"]), []).append(
                            (exchange["status"], body.read(), location)
                        )

    def send(session, request, **kwargs):
        answers = recorded.get((request.method, request.url))
        if not answers:
            raise requests.ConnectionError(f"nothing recorded for {request.method} {request.url}")
        status, body, location = answers.pop(0) if len(answers) > 1 else answers[0]
        response = requests.Response()
        response.status_code = status
        response.headers.update(location)
        response.raw = io.BytesIO(body)
        response.url = request.url
        response.request = request
        # requests follows redirects inside the send this replaces, as it does here
        if kwargs.pop("allow_redirects", True) and response.is_redirect:
            history = [response, *session.resolve_redirects(response, request, **kwargs)]
            response = history.pop()
            response.history = history
        return response

    requests.Session.send = send

    def no_whois(*_args, **_kwargs):
        raise PywhoisError("no WHOIS in a replay")

    whois.whois = no_whois


def point_dns(server):
    """Every dns.resolver.Resolver ace3 makes asks only `server`, with its other settings as
    resolv.conf gives them."""
    import dns.resolver

    host, port = server.rsplit(":", 1)
    original = dns.resolver.Resolver.__init__

    def init(resolver, *args, **kwargs):
        original(resolver, *args, **kwargs)
        resolver.nameservers = [host]
        resolver.port = int(port)

    dns.resolver.Resolver.__init__ = init


def fake_snort_index(path):
    """The snort module's Redis index of `path`, built by ace3's own _build_signature_db into a dict
    that answers the calls it and extract_signature make."""
    import saq.modules.snort as snort

    class FakeRedis(dict):
        def set(self, key, value, **_kwargs):
            self[key] = value
            return True

        def get(self, key):
            return dict.get(self, key)

        def delete(self, key):
            self.pop(key, None)

    fake = FakeRedis()
    snort._build_signature_db(path, get_redis_connection=lambda: fake)
    snort.extract_signature.__defaults__ = (lambda: fake,)


def fake_brocess(path):
    """saq.brocess's two smtplog counts, answered from the rows in `path` as MySQL answers
    `SELECT SUM(numconnections) ... WHERE source = %s [AND destination = %s]`: varbinary columns
    compared byte for byte, NULL counts left out, and no row summing to NULL, which ace3 reads as 0."""
    import saq.modules.email.fa as fa

    with open(path) as fp:
        rows = json.load(fp)["smtplog"]

    def total(matching):
        counts = [count for source, destination, count in rows if matching(source, destination) and count is not None]
        return sum(counts) if counts else 0

    def by_source(source_email_address):
        return total(lambda source, _: source.encode() == source_email_address.encode())

    def by_conversation(source_email_address, dest_email_address):
        return total(
            lambda source, destination: source.encode() == source_email_address.encode()
            and destination.encode() == dest_email_address.encode()
        )

    fa.query_brocess_by_source_email = by_source
    fa.query_brocess_by_email_conversation = by_conversation


def fake_observable_tags(path):
    """ace3's observables, observable_tag_mapping and tags tables, as user_defined_tagging's one SELECT
    reads them (saq/modules/tag.py): the names mapped to an observable's type and the sha256 of its
    value, in the order the file lists them. `path` holds {"tags": [{"type", "value", "tag"}]}; a
    file's value is its sha256, which is what ace3's FileObservable.sha256_hash is."""
    import contextlib

    import saq.modules.tag as tag

    with open(path) as fp:
        mappings = json.load(fp)["tags"]

    def sha256_of(kind, value):
        return value.lower() if kind == "file" else hashlib.sha256(value.encode()).hexdigest()

    class Cursor:
        def __init__(self):
            self.rows = []

        def execute(self, sql, params=()):
            assert "observable_tag_mapping" in sql, sql
            kind, sha256 = params
            self.rows = [
                (m["tag"],) for m in mappings if m["type"] == kind and sha256_of(m["type"], m["value"]) == sha256.lower()
            ]

        def __iter__(self):
            return iter(self.rows)

    class Connection:
        def cursor(self):
            return Cursor()

    @contextlib.contextmanager
    def get_db_connection(name="ace"):
        assert name == "ace", name
        yield Connection()

    tag.get_db_connection = get_db_connection


def fake_detections(path):
    """The Redis cache `ace observables export` keeps for observable_detection
    (saq/observables/export/redis_cache.py): a key `<type>:<value>` for each observable enabled for
    detection. `path` holds {"detections": [{"type", "value"}]}."""
    import saq.modules.observable_detection as detection

    with open(path) as fp:
        keys = {f"{d['type']}:{d['value']}" for d in json.load(fp)["detections"]}

    class Redis:
        def get(self, key):
            return b"1" if key in keys else None

    detection.get_redis_connection = lambda *args, **kwargs: Redis()


def export_detections(path):
    """ace3's export of the observables enabled for detection to YARA rules, which its cron runs every
    minute (bin/export-observables, saq/observables/export/yara.py), run once with ace3's own code and
    settings into the signature directory the local scanner loads. The detections' rows are `path`'s,
    each with its place in the file from 1 as its id, as tests/e2e/run gives ace4's entries the same ids
    (PLAN.md 7.16). The YARA module reads a matched `$obsd_<id>` string's row through get_db
    (saq/modules/file_analysis/yara.py), which answers from the same file."""
    import types

    import saq.modules.file_analysis.yara as yara_module
    from saq.configuration import get_config
    from saq.observables.export.yara import YaraObservableExport

    with open(path) as fp:
        detections = json.load(fp)["detections"]
    by_type, rows = {}, {}
    for row_id, detection in enumerate(detections, start=1):
        by_type.setdefault(detection["type"], []).append({"id": row_id, "value": detection["value"]})
        rows[row_id] = types.SimpleNamespace(type=detection["type"], value=detection["value"])
    export = YaraObservableExport(get_config().get_observable_export_config("yara"))
    export.publish(export.build_export_list(by_type))

    class Db:
        def get(self, model, row_id):
            # $obs_ strings name ace3's legacy observables rows, of which there are none
            return rows.get(row_id) if model is yara_module.db_ObservableDetection else None

    yara_module.get_db = lambda: Db()


def exported_rule_dates(result):
    """Takes the `date` meta out of each match of a rule the export generated: its template writes the
    day the export ran (remove_export_dates in crates/ace-core/src/normal.rs). ace3's namespace is the
    rule directory's path."""
    for match in result["details"].get("scan_results") or []:
        namespace = str(match.get("namespace") or "").rstrip("/")
        if os.path.basename(namespace) == "observable_export" and isinstance(match.get("meta"), dict):
            match["meta"].pop("date", None)


class FakeBrocess:
    """brocess's smtplog and thread store, in memory, answering the statements ace3's email logger
    (saq/modules/email/logging.py) and its thread code (saq/modules/email/conversation.py) send, as
    MySQL would: each hash is UNHEX(SHA2(text, 256)) of the text's UTF-8, HEX() is upper case, a
    duplicate key leaves its row, and NOW() is the store's "now". Rows come back in the order InnoDB
    reads them: by id through the thread index, and by thread hash then id for a list of threads. A
    statement it doesn't know fails the run."""

    def __init__(self, path):
        with open(path) as fp:
            store = json.load(fp)
        self.now = store["now"]
        self.smtplog = [list(row) for row in store.get("smtplog", [])]
        self.messages = [dict(row) for row in store.get("email_thread_message", [])]
        self.domains = [dict(row) for row in store.get("email_thread_domain", [])]
        self.reads = []

    def rows(self):
        return {
            "now": self.now,
            "smtplog": self.smtplog,
            "email_thread_message": self.messages,
            "email_thread_domain": self.domains,
        }

    @staticmethod
    def sha(text):
        return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()

    def connection(self):
        import contextlib

        store = self

        class Cursor:
            def __init__(self):
                self.result = []
                self.rowcount = 0

            def execute(self, sql, params=()):
                self.result = store.execute(" ".join(sql.split()), tuple(params))
                self.rowcount = len(self.result)

            def fetchall(self):
                return list(self.result)

            def fetchone(self):
                return self.result[0] if self.result else None

            def __iter__(self):
                return iter(list(self.result))

        class Connection:
            server_status = 0

            def cursor(self):
                return Cursor()

            def commit(self):
                pass

            def rollback(self):
                pass

        @contextlib.contextmanager
        def get_db_connection(name="ace"):
            assert name == "brocess", name
            yield Connection()

        return get_db_connection

    def execute(self, sql, params):
        import datetime

        def text(value):
            return None if value is None else str(value)

        def when(value):
            if value is None:
                return None
            if isinstance(value, datetime.datetime):
                return value.strftime("%Y-%m-%d %H:%M:%S")
            return value

        def as_datetime(value):
            return None if value is None else datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")

        if sql.startswith("INSERT INTO smtplog"):
            # ace3 cuts each to 255 bytes, which the fixtures' addresses are well under
            source, destination = (p.decode("utf-8") for p in params)
            for row in self.smtplog:
                if row[0].encode() == source.encode() and row[1].encode() == destination.encode():
                    row[2] += 1
                    return [()]
            stamp = datetime.datetime.strptime(self.now, "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
            self.smtplog.append([source, destination, 1, float(int(stamp.timestamp()))])
            return [()]
        if sql.startswith("INSERT INTO email_thread_message"):
            (thread_id, _, message_id, _, in_reply_to, subject, _, from_address, from_domain, direction,
             message_date) = params
            key = (self.sha(thread_id), self.sha(message_id))
            if any((m["thread_id_hash"], m["message_id_hash"]) == key for m in self.messages):
                return []
            self.messages.append({
                "id": len(self.messages) + 1, "insert_date": self.now, "thread_id": thread_id,
                "thread_id_hash": key[0], "message_id": message_id, "message_id_hash": key[1],
                "in_reply_to": text(in_reply_to), "normalized_subject": subject,
                "normalized_subject_hash": None if subject is None else self.sha(subject),
                "from_address": from_address, "from_domain": from_domain, "direction": direction,
                "message_date": when(message_date),
            })
            return [()]
        if sql.startswith("INSERT INTO email_thread_domain"):
            thread_id, _, message_id, domain, address, role, *entry = params
            thread_hash = self.sha(thread_id)
            entry_hash = self.sha("\x1f".join(entry))
            if any((d["thread_id_hash"], d["entry_hash"]) == (thread_hash, entry_hash) for d in self.domains):
                return []
            self.domains.append({
                "id": len(self.domains) + 1, "thread_id": thread_id, "thread_id_hash": thread_hash,
                "message_id_hash": self.sha(message_id), "domain": domain, "address": address, "role": role,
                "entry_hash": entry_hash, "numseen": 1, "firstseendate": self.now,
            })
            return [()]

        def domains_of(thread_hashes, by_thread):
            rows = [d for d in self.domains if d["thread_id_hash"] in thread_hashes]
            return sorted(rows, key=lambda d: (d["thread_id_hash"], d["id"]) if by_thread else d["id"])

        def subject_threads(subject):
            digest = self.sha(subject)
            return {m["thread_id_hash"] for m in self.messages if m["normalized_subject_hash"] == digest}

        if sql.startswith("SELECT domain, address, role, firstseendate FROM email_thread_domain WHERE thread_id_hash = UNHEX(SHA2(%s, 256))"):
            rows = [(d["domain"], d["address"], d["role"], as_datetime(d["firstseendate"]))
                    for d in domains_of({self.sha(params[0])}, False)]
            return rows
        if sql.startswith("SELECT HEX(d.thread_id_hash), d.domain, d.address, d.role, d.firstseendate FROM email_thread_domain d WHERE d.thread_id_hash IN ( SELECT m.thread_id_hash FROM email_thread_message m WHERE m.normalized_subject_hash = UNHEX(SHA2(%s, 256)) )"):
            rows = [(d["thread_id_hash"], d["domain"], d["address"], d["role"], as_datetime(d["firstseendate"]))
                    for d in domains_of(subject_threads(params[0]), False)]
            return rows
        if sql.startswith("SELECT COUNT(*) FROM email_thread_message WHERE thread_id_hash = UNHEX(SHA2(%s, 256))"):
            digest = self.sha(params[0])
            return [(sum(1 for m in self.messages if m["thread_id_hash"] == digest),)]
        message_columns = ("thread_id", "message_id", "message_id_hash", "in_reply_to", "normalized_subject",
                           "from_address", "from_domain", "direction", "message_date", "insert_date")

        def message_row(m):
            return tuple(as_datetime(m[c]) if c in ("message_date", "insert_date") else m[c] for c in message_columns)

        if sql.startswith("SELECT HEX(thread_id_hash), normalized_subject, thread_id, message_id FROM email_thread_message WHERE message_id_hash = UNHEX(SHA2(%s, 256)) LIMIT 1"):
            digest = self.sha(params[0])
            found = [m for m in self.messages if m["message_id_hash"] == digest]
            return [(m["thread_id_hash"], m["normalized_subject"], m["thread_id"], m["message_id"]) for m in found[:1]]
        if sql.startswith("SELECT thread_id, message_id, HEX(message_id_hash), in_reply_to, normalized_subject, from_address, from_domain, direction, message_date, insert_date FROM email_thread_message WHERE message_id_hash = UNHEX(SHA2(%s, 256)) LIMIT 1"):
            digest = self.sha(params[0])
            return [message_row(m) for m in self.messages if m["message_id_hash"] == digest][:1]
        if sql.startswith("SELECT thread_id, message_id, HEX(message_id_hash), in_reply_to, normalized_subject, from_address, from_domain, direction, message_date, insert_date FROM email_thread_message WHERE thread_id_hash IN ("):
            *hexes, limit = params
            rows = [m for m in self.messages if m["thread_id_hash"] in {h.upper() for h in hexes}]
            rows.sort(key=lambda m: (m["message_date"] is None, m["message_date"] or "", m["insert_date"], m["id"]))
            return [message_row(m) for m in rows[:limit]]
        if sql.startswith("SELECT HEX(message_id_hash), domain, address, role, firstseendate FROM email_thread_domain WHERE thread_id_hash IN ("):
            return [(d["message_id_hash"], d["domain"], d["address"], d["role"], as_datetime(d["firstseendate"]))
                    for d in domains_of({h.upper() for h in params}, True)]
        if sql.startswith("SELECT HEX(thread_id_hash), MIN(message_date), MIN(insert_date) FROM email_thread_message WHERE normalized_subject_hash = UNHEX(SHA2(%s, 256)) GROUP BY thread_id_hash"):
            digest = self.sha(params[0])
            groups = {}
            for m in self.messages:
                if m["normalized_subject_hash"] == digest:
                    groups.setdefault(m["thread_id_hash"], []).append(m)
            result = []
            for thread_hash in sorted(groups):
                dates = [m["message_date"] for m in groups[thread_hash] if m["message_date"] is not None]
                result.append((thread_hash, as_datetime(min(dates)) if dates else None,
                               as_datetime(min(m["insert_date"] for m in groups[thread_hash]))))
            return result
        if sql.startswith("SELECT message_id FROM email_thread_message WHERE message_id_hash IN ("):
            digests = {self.sha(p) for p in params}
            return [(m["message_id"],) for m in self.messages if m["message_id_hash"] in digests]
        raise RuntimeError(f"FakeBrocess doesn't know {sql}")


def fake_brocess_store(path):
    """Points ace3's email logger and thread code at a FakeBrocess over the rows in `path`."""
    import saq.modules.email.conversation as conversation
    import saq.modules.email.logging as email_logging

    store = FakeBrocess(path)
    conversation.get_db_connection = store.connection()
    email_logging.get_db_connection = store.connection()

    # what the logger's reads answered, as ace4's email-thread-domains read answers them
    established, count = conversation.get_established_domains, conversation.get_thread_message_count

    def get_established_domains(context):
        found = established(context)
        store.reads.append({"established": [
            {"domain": d.domain, "address": d.address, "role": d.role,
             "first_seen": str(d.firstseendate) if d.firstseendate else None}
            for d in found
        ]})
        return found

    def get_thread_message_count(thread_id):
        found = count(thread_id)
        store.reads.append({"thread_message_count": found})
        return found

    conversation.get_established_domains = get_established_domains
    conversation.get_thread_message_count = get_thread_message_count

    # what the thread module's read answered, as ace4's email-thread read answers it
    import saq.modules.email.thread as email_thread

    get_conversation = email_thread.get_conversation

    def recorded_conversation(message_id, **caps):
        found = get_conversation(message_id, **caps)
        store.reads.append({"conversation": None if found is None else conversation_form(found)})
        return found

    email_thread.get_conversation = recorded_conversation
    return store


class FakeEmailArchive:
    """ace3's email-archive database, in memory, answering the statements saq/email_archive/local.py
    and the URL pivot module send, as MySQL would: each hash is UNHEX(SHA2(text, 256)) of the text's
    UTF-8, HEX() is upper case, INSERT IGNORE leaves a duplicate key's row, and a NULL or a duplicate
    in email_history raises IntegrityError, which ace3 passes over. One archive server, ace3-node,
    so the paths don't carry the container's hostname. A statement it doesn't know fails the run."""

    HOSTNAME = "ace3-node"

    def __init__(self):
        self.archive = []
        self.index = []
        self.history = []
        self.reads = []

    def rows(self):
        return {
            "archive": [
                {"archive_id": a["archive_id"], "hash": a["hash"], "insert_date": a["insert_date"]}
                for a in self.archive
            ],
            "archive_index": sorted(
                ({"field": i["field"], "hash": i["hash"], "archive_id": i["archive_id"]} for i in self.index),
                key=lambda i: (i["archive_id"], i["field"], i["hash"]),
            ),
            "email_history": [
                {"message_id": h["message_id"], "message_id_hash": h["message_id_hash"],
                 "recipient": h["recipient"], "recipient_hash": h["recipient_hash"]}
                for h in self.history
            ],
        }

    @staticmethod
    def sha(text):
        return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()

    def connection(self, names):
        import contextlib

        store = self

        class Cursor:
            def __init__(self):
                self.result = []
                self.rowcount = 0
                self.lastrowid = 0

            def execute(self, sql, params=()):
                self.result, self.lastrowid = store.execute(" ".join(sql.split()), tuple(params or ()))
                self.rowcount = len(self.result)

            def fetchall(self):
                return list(self.result)

            def fetchone(self):
                return self.result[0] if self.result else None

            def __iter__(self):
                return iter(list(self.result))

        class Connection:
            server_status = 0

            def cursor(self):
                return Cursor()

            def commit(self):
                pass

            def rollback(self):
                pass

        @contextlib.contextmanager
        def get_db_connection(name="ace"):
            assert name in names, name
            yield Connection()

        return get_db_connection

    def execute(self, sql, params):
        import pymysql

        def when(value):
            return value.strftime("%Y-%m-%d %H:%M:%S") if hasattr(value, "strftime") else str(value)

        if sql == "INSERT IGNORE INTO archive ( server_id, hash, insert_date ) VALUES ( %s, UNHEX(%s), %s )":
            _, digest, insert_date = params
            key = (digest.upper(), when(insert_date))
            if any((a["hash"], a["insert_date"]) == key for a in self.archive):
                return [], 0
            archive_id = len(self.archive) + 1
            self.archive.append({"archive_id": archive_id, "hash": key[0], "insert_date": key[1]})
            return [], archive_id
        if sql == "SELECT archive_id FROM archive WHERE server_id = %s AND hash = UNHEX(%s) AND insert_date = %s":
            _, digest, insert_date = params
            key = (digest.upper(), when(insert_date))
            return [(a["archive_id"],) for a in self.archive if (a["hash"], a["insert_date"]) == key], 0
        if sql == "INSERT IGNORE INTO archive_index ( field, hash, archive_id, insert_date ) VALUES ( %s, UNHEX(SHA2(%s, 256)), %s, %s )":
            field, value, archive_id, insert_date = params
            row = {"field": field, "hash": self.sha(value), "archive_id": archive_id, "insert_date": when(insert_date)}
            if row not in self.index:
                self.index.append(row)
            return [], 0
        if sql.startswith("INSERT INTO email_history ( insert_date, message_id, message_id_hash, recipient, recipient_hash ) VALUES"):
            insert_date, message_id, _, recipient, _ = params
            if message_id is None or recipient is None:
                raise pymysql.err.IntegrityError(1048, "Column cannot be null")
            row = {"insert_date": when(insert_date), "message_id": message_id,
                   "message_id_hash": self.sha(message_id), "recipient": recipient,
                   "recipient_hash": self.sha(recipient)}
            if any((h["message_id_hash"], h["recipient_hash"], h["insert_date"])
                   == (row["message_id_hash"], row["recipient_hash"], row["insert_date"]) for h in self.history):
                raise pymysql.err.IntegrityError(1062, "Duplicate entry")
            self.history.append(row)
            return [], 0
        if sql.startswith("SELECT archive_server.hostname, HEX(archive.hash) FROM archive JOIN archive_server"):
            digest = self.sha(params[0])
            ids = {i["archive_id"] for i in self.index if i["field"] == "message_id" and i["hash"] == digest}
            found = sorted((a for a in self.archive if a["archive_id"] in ids),
                           key=lambda a: a["insert_date"], reverse=True)
            self.reads.append({"query_by_message_id": params[0],
                               "hash": found[0]["hash"] if found else None})
            return [(self.HOSTNAME, a["hash"]) for a in found], 0
        if sql == "SELECT COUNT(DISTINCT(archive_id)) FROM archive_index WHERE field = 'url' AND hash = UNHEX(SHA2(%s, 256))":
            digest = self.sha(params[0])
            count = len({i["archive_id"] for i in self.index if i["field"] == "url" and i["hash"] == digest})
            self.reads.append({"url_count": params[0], "count": count})
            return [(count,)], 0
        if sql == "SELECT server_id FROM archive_server WHERE hostname = %s":
            return [(1,)], 0
        raise RuntimeError(f"FakeEmailArchive doesn't know {sql}")


def use_encryption_key(key_hex):
    """ace3's encryption, initialized with this key, as its password would load it."""
    from saq.environment import get_global_runtime_settings

    settings = get_global_runtime_settings()
    settings.encryption_key = bytes.fromhex(key_hex)
    settings.encryption_initialized = True


def fake_email_archive(path, work):
    """Points ace3's email archive at a FakeEmailArchive, and archives the emails `path` lists with
    ace3's own archive_email, each at its insert_date, indexing the URLs it names. An email marked
    `delete_file` loses its file once archived, as one archived by another node is missing here."""
    import datetime

    import saq.email_archive.local as local
    import saq.modules.email.archive as archive_module
    import saq.modules.email.correlation as correlation
    from saq.constants import DB_EMAIL_ARCHIVE, EMAIL_ARCHIVE_FIELD_URL
    from saq.email_archive import archive_email, get_archive_path_by_hash, index_email_archive

    store = FakeEmailArchive()
    connection = store.connection({DB_EMAIL_ARCHIVE, "email_archive"})
    local.get_db_connection = connection
    archive_module.get_db_connection = connection
    correlation.get_db_connection = connection
    correlation.get_email_archive_sections = lambda: ["email_archive"]
    local.EmailArchiveLocal.get_email_archive_local_server_name = lambda self: FakeEmailArchive.HOSTNAME
    local.EmailArchiveLocal.get_email_archive_server_id = lambda self: 1

    with open(path) as fp:
        seed = json.load(fp)
    base = os.path.dirname(os.path.abspath(path))
    for email in seed.get("emails", []):
        insert_date = datetime.datetime.strptime(email["insert_date"], "%Y-%m-%d %H:%M:%S")
        result = archive_email(os.path.join(base, email["file"]), email["message_id"], email["recipients"], insert_date)
        with connection(DB_EMAIL_ARCHIVE) as db:
            cursor = db.cursor()
            for url in email.get("urls", []):
                index_email_archive(db, cursor, result.archive_id, EMAIL_ARCHIVE_FIELD_URL, url, insert_date)
        if email.get("delete_file"):
            os.remove(get_archive_path_by_hash(result.hash))
    return store


def conversation_form(conversation):
    """A Conversation as ace4's email-thread read answers one."""

    def when(value):
        return value.strftime("%Y-%m-%d %H:%M:%S") if value else None

    def participant(p):
        return {"message_id_hex": p.message_id_hex, "domain": p.domain, "address": p.address,
                "role": p.role, "first_seen": when(p.firstseendate)}

    return {
        "anchor_message_id": conversation.anchor_message_id,
        "normalized_subject": conversation.normalized_subject,
        "thread_count": conversation.thread_count,
        "thread_method": conversation.thread_method,
        "link_domains": conversation.link_domains,
        "thread_message_counts": conversation.thread_message_counts,
        "domain_roles": {d: sorted(r) for d, r in sorted(conversation.domain_roles.items())},
        "domain_addresses": {d: sorted(a) for d, a in sorted(conversation.domain_addresses.items())},
        "messages": [{
            "thread_id": m.thread_id, "message_id": m.message_id, "message_id_hex": m.message_id_hex,
            "in_reply_to": m.in_reply_to, "normalized_subject": m.normalized_subject,
            "from_address": m.from_address, "from_domain": m.from_domain, "direction": m.direction,
            "message_date": when(m.message_date), "insert_date": when(m.insert_date),
        } for m in conversation.messages],
        # the participants in the order Conversation keeps them: those tied to no message, then each
        # message's, in the order the first of each was read
        "participants": [participant(p) for p in conversation.unattributed_participants]
        + [participant(p) for ps in conversation.participants_by_message.values() for p in ps],
        "truncated": conversation.truncated,
        "roles_truncated": False,
    }


def record_fluent_bit():
    """Keeps what ace3 sends to fluent-bit, by tag, instead of sending it."""
    from fluent import sender

    sent = []

    def emit(self, label, data):
        sent.append({"tag": ".".join((self.tag, label)) if label else self.tag, "record": json_safe(data)})
        return True

    sender.FluentSender.emit = emit
    return sent


# What the normal form calls each ace3 analysis, and the fields of a result that describe the run
# rather than the sample: RUN_FIELDS in crates/ace-core/src/normal.rs, by ace3's class.
TREE_MODULES = {
    "EmailAnalysis": "email_analyzer",
    "FileTypeAnalysis": "file_type",
    "FQDNAnalysis": "fqdn_analyzer",
    "EmailConversationFrequencyAnalysis": "email_conversation_frequency_analyzer",
    "SnortSignatureAnalysis_v1": "snort_signature_analysis_v1",
    "ArchiveAnalysis": "archive",
    "OLEVBA_Analysis_v1_2": "olevba_v1_2",
    "MSOfficeEncryptionAnalysis": "msoffice_encryption_analyzer",
    "PCodeAnalysis": "pcodedmp",
    "PDFAnalysis": "pdf_analyzer",
    "RdapAnalysis": "rdap_analyzer",
    "RTFOLEObjectAnalysis": "rtfole",
    "XLMMacroDeobfuscatorAnalysis": "xlmdeobfuscator",
    "YaraScanResults_v3_4": "yara_scanner_v3_4",
    "SplunkAPIAnalysis": "proxy_domain_splunk",
    "NRDAnalysis": "nrd_analyzer",
    "URLExtractionAnalysis": "url_extraction",
    "IOCExtractionAnalysis": "ioc_extraction",
    "FileHashAnalysis": "file_hash_analyzer",
    "BinaryFileAnalysis": "binary_file_analyzer",
    "LnkParseAnalysis": "lnk_parser",
    "X509Analysis": "x509_analyzer",
    "DHashImageAnalysis": "dhash",
    "CommandLineAnalysis": "command_line_analyzer",
    "FileLocationAnalysis": "file_location_analysis",
    "FilePathAnalysis": "file_path_analysis",
    "NetworkIdentifierAnalysis": "network_identifier",
    "ParseURLAnalysis": "parse_url",
    "IDNAAnalysis": "idna_analyzer",
    "ApexDomainAnalysis": "apex_domain_analyzer",
    "EmailAddressFQDNAnalysis": "email_address_fqdn_analyzer",
    "ProtectedURLAnalysis": "protected_url_analyzer",
    "HTMLDataURLAnalysis": "html_data_url_extraction",
    "HARAnalysis": "har_extraction",
    "HTMLJavaScriptExtractionAnalysis": "html_js_extraction",
    "JavaScriptDeobfuscationAnalysis": "javascript_deobfuscation",
    "PhishkitAnalysis": "phishkit_analyzer",
    "MHTMLAnalysis": "mhtml",
    "OneNoteFileAnalysis": "onenote_extraction",
    "OfficeParserAnalysis3": "officeparser3",
    "OfficeXMLRelationshipExternalURLAnalysis": "office_xml_rel",
    "XMLBinaryDataAnalysis": "xml_binary_analyzer",
    "XMLPlainTextAnalysis": "xml_plain_text_analyzer",
    "ExtractedOLEAnalysis": "extracted_ole_analyzer",
    "HiddenMIMEAnalysis": "hidden_mime",
    "ActiveMimeAnalysis": "active_mime",
    "MicrosoftScriptEncodingAnalysis": "microsoft_script_encoding_analysis",
    "ExtractedRTFAnalysis": "extracted_rtf_analyzer",
    "VBScriptAnalysis": "vbscript_analyzer",
    "NoWhiteSpaceAnalysis": "nowhitespace_analyzer",
    "ZipEncryptionAnalysis": "zip_encryption_analyzer",
    "RarEncryptionAnalysis": "rar_encryption_analyzer",
    "PDFEncryptionAnalysis": "pdf_encryption_analyzer",
    "LureURLAnalysis": "lure_url_analyzer",
    "MailboxEmailAnalysis": "mailbox_email_analyzer",
    "EmailConversationAttachmentAnalysis": "email_conversation_attachment_analyzer",
    "EmailConversationLinkAnalysis": "email_conversation_link_analyzer",
    "EmailArchiveResults": "email_archiver",
    "EncryptedArchiveAnalysis": "encrypted_archive_analyzer",
    "URLEmailPivotAnalysis_v2": "url_email_pivot_analyzer",
    "MessageIDAnalysisV2": "message_id_analyzer_v2",
    "PDFTextAnalysis": "pdftotext",
    "PDFLinkTextAnalysis": "pdf_link_text",
    "ExifAnalysis": "exif",
    "QRCodeAnalysis": "qrcode",
    "OCRAnalysis": "ocr",
    "SsdeepAnalysis": "ssdeep",
    "JavaClassDecompilerAnalysis": "java_class_decompiler",
    "UPXAnalysis": "upx",
    "AutoItAnalysis": "autoit",
    "De4dotAnalysis": "de4dot",
    "IlspyAnalysis": "ilspy",
    "DMGAnalysis": "dmg_analyzer",
    "CVE_2021_30657_Analysis": "cve_2021_30657_analyzer",
    "PcapAnalysis": "pcap_analyzer",
    "PcapTlsDecryptionAnalysis": "pcap_tls_decryption",
    "TlsKeylogAnalysis": "tls_keylog",
    "UserDefinedTaggingAnalysis": "user_defined_tagging",
    "SiteTagAnalysis": "site_tagger",
    "ObservableDetectionAnalysis": "observable_detection",
    "ObservableModifierAnalysis": "observable_modifier",
}


def tree_module(analysis):
    """The module a result is named by in a tree. ace3's pcap_dns, pcap_tls, pcap_http and pcap_files
    are instances of one class, PcapCategoryAnalyzer, each named by its instance."""
    class_name = type(analysis).__name__
    if class_name == "PcapCategoryAnalysis":
        return f"pcap_{analysis.instance}"
    return TREE_MODULES.get(class_name, class_name)

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
    "NRDAnalysis": ["details/matched_at"],
    # the uuid ace3 gives an observable is new each run, and ace4's observables have none
    "LureURLAnalysis": ["details/primary/observable_uuid", "details/candidates/*/observable_uuid"],
}
# ace3's excluded_analysis holds `module:<class ...>` strings
TREE_EXCLUDED = {
    "PhishkitAnalyzer": "phishkit_analyzer",
    "JavaScriptDeobfuscationAnalyzer": "javascript_deobfuscation",
    "EmailAnalyzer": "email_analyzer",
    "FQDNAnalyzer": "fqdn_analyzer",
    "EmailConversationFrequencyAnalyzer": "email_conversation_frequency_analyzer",
    "SnortSignatureAnalyzer_v1": "snort_signature_analysis_v1",
    "MessageIDAnalyzerV2": "message_id_analyzer_v2",
    "ArchiveAnalyzer": "archive",
    "OLEVBA_Analyzer_v1_2": "olevba_v1_2",
    "RTFOLEObjectAnalyzer": "rtfole",
    "MSOfficeEncryptionAnalyzer": "msoffice_encryption_analyzer",
    "PCodeAnalyzer": "pcodedmp",
    "PDFAnalyzer": "pdf_analyzer",
    "PDFTextAnalyzer": "pdftotext",
    "PDFLinkTextAnalyzer": "pdf_link_text",
    "ExifAnalyzer": "exif",
    "QRCodeAnalyzer": "qrcode",
    "OCRAnalyzer": "ocr",
    "FileHashAnalyzer": "file_hash_analyzer",
    "FileTypeAnalyzer": "file_type",
    "XLMMacroDeobfuscatorAnalyzer": "xlmdeobfuscator",
    "YaraScanner_v3_4": "yara_scanner_v3_4",
    "URLExtractionAnalyzer": "url_extraction",
    "IOCExtractionAnalyzer": "ioc_extraction",
    "IDNAAnalyzer": "idna_analyzer",
    "ApexDomainAnalyzer": "apex_domain_analyzer",
    "HTMLDataURLAnalyzer": "html_data_url_extraction",
    "HARExtractor": "har_extraction",
    "HTMLJavaScriptExtractor": "html_js_extraction",
    "MHTMLAnalysisModule": "mhtml",
    "OCRAnalyzer": "ocr",
    "OneNoteFileAnalyzer": "onenote_extraction",
    "OfficeParserAnalyzer3": "officeparser3",
    "OfficeXMLRelationshipExternalURLAnalyzer": "office_xml_rel",
    "XMLBinaryDataAnalyzer": "xml_binary_analyzer",
    "XMLPlainTextAnalyzer": "xml_plain_text_analyzer",
    "ExtractedOLEAnalyzer": "extracted_ole_analyzer",
    "HiddenMIMEAnalyzer": "hidden_mime",
    "ActiveMimeAnalyzer": "active_mime",
    "MicrosoftScriptEncodingAnalyzer": "microsoft_script_encoding_analysis",
    "ExtractedRTFAnalyzer": "extracted_rtf_analyzer",
    "VBScriptAnalyzer": "vbscript_analyzer",
    "NoWhiteSpaceAnalyzer": "nowhitespace_analyzer",
    "ZipEncryptionAnalyzer": "zip_encryption_analyzer",
    "RarEncryptionAnalyzer": "rar_encryption_analyzer",
    "PDFEncryptionAnalyzer": "pdf_encryption_analyzer",
    "LureURLAnalyzer": "lure_url_analyzer",
    "MailboxEmailAnalyzer": "mailbox_email_analyzer",
    "EmailConversationAttachmentAnalyzer": "email_conversation_attachment_analyzer",
    "EmailConversationLinkAnalyzer": "email_conversation_link_analyzer",
    "AutoItAnalyzer": "autoit",
    "De4dotAnalyzer": "de4dot",
    "IlspyAnalyzer": "ilspy",
    "RdapAnalyzer": "rdap_analyzer",
}


def tree_excluded(excluded):
    """The module an entry of ace3's excluded_analysis names: `module:<class 'module.Class'>`, as ace3's
    own exclude_analysis writes it, or `module:Class`, as an observable modifier rule's does."""
    name = excluded.rsplit(".", 1)[-1].removesuffix("'>")
    name = name.rsplit(":", 1)[-1]
    return TREE_EXCLUDED.get(name, name)


def modifier_modules(details):
    """An ObservableModifierAnalysis's details with the modules its rules' actions name as ace4 names
    them: ace3's rules name an analyzer class to exclude and an Analysis class to reset."""
    for match in details.get("matched_rules") or []:
        applied = match.get("actions_applied") or {}
        if isinstance(applied.get("exclude_analysis"), list):
            applied["exclude_analysis"] = [tree_excluded(m) for m in applied["exclude_analysis"]]
        if isinstance(applied.get("reset_analysis"), list):
            applied["reset_analysis"] = [
                TREE_MODULES.get(m.rsplit(":", 1)[-1], m) for m in applied["reset_analysis"]
            ]
    return details


def remove_at(value, segments):
    if isinstance(value, dict) and len(segments) == 1:
        value.pop(segments[0], None)
    elif isinstance(value, dict):
        if segments[0] in value:
            remove_at(value[segments[0]], segments[1:])
    elif isinstance(value, list) and segments[0] == "*":
        for item in value:
            remove_at(item, segments[1:])


def carrying_email(work, body, attachment, name):
    """An email with fixed headers carrying the file at attachment as name, its body the file body."""
    import email.message

    message = email.message.EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "recipient@example.com"
    message["Subject"] = "the attached file"
    message["Date"] = "Mon, 09 Nov 2026 12:00:00 +0000"
    message["Message-ID"] = "<carrying-email@example.com>"
    if body == "-":
        message.make_mixed()
    else:
        with open(body, encoding="utf-8") as fp:
            text = fp.read()
        if body.endswith(".html"):
            message.set_content(text, subtype="html")
        elif body.endswith(".both"):
            plain, html = text.split("\n--html--\n", 1)
            message.set_content(plain)
            message.add_alternative(html, subtype="html")
        else:
            message.set_content(text)
    with open(attachment, "rb") as fp:
        message.add_attachment(fp.read(), maintype="application", subtype="octet-stream", filename=name)
    message.set_boundary("carrying-email")
    path = os.path.join(work, "email.rfc822")
    with open(path, "wb") as fp:
        fp.write(message.as_bytes())
    return path


def carrying_email_body(root, target):
    """The body parts of the email search_down() finds from target, as the encryption modules read them
    since ace3's 1998ca56 (EmailAnalysis.body_parts), in order, each with whether it is HTML."""
    import base64

    from saq.analysis.search import search_down
    from saq.modules.email.rfc822 import EmailAnalysis, is_html_body_part

    for analysis in root.all_analysis:
        analysis.load_details()
    found = search_down(target, lambda obj: isinstance(obj, EmailAnalysis) and obj.email is not None)
    if not found:
        return None
    parts = []
    for part in found.body_parts:
        with open(part.full_path, "rb") as fp:
            parts.append({
                "path": part.file_path,
                "html": is_html_body_part(part),
                "body": base64.b64encode(fp.read()).decode(),
            })
    return {"parts": parts}


def tree_time(time):
    """As chrono's to_rfc3339_opts(AutoSi, true) writes it."""
    import datetime

    time = time.astimezone(datetime.timezone.utc)
    text = time.strftime("%Y-%m-%dT%H:%M:%S")
    if time.microsecond:
        text += f".{time.microsecond // 1000:03d}" if time.microsecond % 1000 == 0 else f".{time.microsecond:06d}"
    return text + "Z"


# The Python the ports say ace3 runs, where a tool prints its interpreter's version: pdf-parser.py's
# first line and rtfobj's banner. ace3's image is built from python:3.14-trixie, whose patch version
# is whatever the tag held when the image was built (3.14.10 on the machine the ports were made
# against, 3.14.9 on the next), so it says nothing about ace3's code. The trees put ace3's side as
# the ports write it, and any other byte that differs still shows.
PORT_PYTHON = "3.14.10"


def port_python_dump(data):
    """A pdf-parser.py dump with the Python its first line names put as the port writes it."""
    import re

    return re.sub(
        rb"\AThis program has not been tested with this version of Python \(\d+\.\d+\.\d+\)\n",
        b"This program has not been tested with this version of Python (" + PORT_PYTHON.encode() + b")\n",
        data,
    )


def rtfole_in_alert_paths(result, files_dir):
    """rtfobj's report names the file and its objects by the paths ace3 gave it, on its node, and
    ace3 lists the objects in its filesystem's order. The port writes paths in the alert and sorts
    them. Its banner names the Python it ran on (PORT_PYTHON). So those three things, and nothing
    else in these fields, are put the same here, and any other difference in the report shows."""
    import re

    from saq.util.strings import format_item_list_for_summary

    details = result["details"]
    for field in ("stdout", "stderr"):
        if isinstance(details[field], str):
            details[field] = details[field].replace(files_dir + "/", "")
    if isinstance(details["stdout"], str):
        details["stdout"] = re.sub(
            r"\A(rtfobj \S+ on Python )\d+\.\d+\.\d+ ", r"\g<1>" + PORT_PYTHON + " ", details["stdout"]
        )
    details["extracted_files"] = sorted(path.replace(files_dir + "/", "") for path in details["extracted_files"])
    if details["extracted_files"]:
        result["summary"] = (
            "RTF OLE Object Analysis: extracted " + format_item_list_for_summary(details["extracted_files"])
        )


def msoffice_in_alert_paths(result, files_dir):
    """office2john.py names the file by the path it was given, on the node, which reaches the summary;
    the port writes the path in the alert, which is put the same here. ace3 kept office2john.py's
    failure in the details too until 2b9fcd2c moved it to Analysis.error, which tree_form holds as the
    result's error, with the same path put the same way. The candidates from the body came out of a set
    until 1998ca56, and were sorted here; they are in the order ace3 makes them now."""
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


SCANNER_JOB = "00000000-0000-4000-8000-000000000000"


def fake_scanners(output, scanner_requests):
    """The scanner clients answer with a copy of `output`, a scan's output directory as the manager
    leaves it, and `scanner_requests` gets what the module asked for, each time it asks.
    `raise:<message>` raises instead."""
    import saq.modules.file_analysis.js as js
    import saq.modules.phishkit as phishkit

    def answer(output_dir, kind):
        if output.startswith("raise:"):
            raise Exception(output[len("raise:"):])
        if kind == "url":
            # phishkit.py's scan_url: a failed scanner that left nothing to harvest raises
            with open(os.path.join(output, "exit.code")) as fp:
                code = int(fp.read().strip() or "0")
            recoverable = any(os.path.exists(os.path.join(output, n)) for n in ("requests.json", "dom.html"))
            if code != 0 and not recoverable:
                with open(os.path.join(output, "std.err")) as fp:
                    raise Exception(f"scan failed: {fp.read()}")
        os.makedirs(output_dir, exist_ok=True)
        files = []
        for root, _, names in os.walk(output):
            for name in names:
                source = os.path.join(root, name)
                dest = os.path.join(output_dir, os.path.relpath(source, output))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copy2(source, dest)
                files.append(dest)
        return files

    def deobfuscate_file(file_path, output_dir, timeout=60, scanner_timeout=30, dom_snapshot_path=None):
        snapshot = None
        if dom_snapshot_path is not None:
            with open(dom_snapshot_path, encoding="utf-8") as fp:
                snapshot = json.load(fp)
        scanner_requests.append({
            "scanner": "js-deobfuscator", "file_name": os.path.basename(file_path), "timeout": timeout,
            "scanner_timeout": scanner_timeout, "dom_snapshot": snapshot,
        })
        return answer(output_dir, "js")

    def scan(kind):
        def submit(target, output_dir, is_async=False, timeout=15, scanner_timeout=15, proxy=None,
                   proxy_fallback_to_direct=False, config_path=None):
            scanner_requests.append({
                "scanner": "phishkit", "kind": kind,
                "target": target if kind == "url" else os.path.basename(target),
                "scanner_timeout": scanner_timeout, "proxy": proxy,
                "proxy_fallback_to_direct": proxy_fallback_to_direct, "config_path": config_path,
            })
            return SCANNER_JOB
        return submit

    def get_async_scan_result(result_id, output_dir, timeout=1):
        return answer(output_dir, scanner_requests[-1].get("kind"))

    js.deobfuscate_file = deobfuscate_file
    phishkit.scan_url = scan("url")
    phishkit.scan_file = scan("file")
    phishkit.get_async_scan_result = get_async_scan_result
    phishkit.get_phishkit_scanner_version = lambda: {}


# ` (crash_id <uuid>)`, which ace3's engine puts after the reason of an analysis whose module raised
CRASH_ID = re.compile(r" \(crash_id [0-9a-f-]{36}\)")


def tree_form(root):
    def members(items):
        return {item: True for item in items}

    observables = {}
    renames = deterministic_id_renames(root)

    def renamed(kind, value):
        return renames.get(value, value) if kind in ("file", "md5", "sha1", "sha256") else value

    # ace3's own order changes from run to run, and two observables can merge below
    for observable in sorted(root.all_observables, key=lambda o: o.file_path if o.type == "file" else ""):
        entry = {
            "tags": members(str(tag) for tag in observable.tags),
            "directives": members(d for d in observable.directives if not d.startswith("yara_meta:")),
            "excluded_analysis": members(tree_excluded(excluded) for excluded in observable.excluded_analysis),
            "relationships": members(
                f"{r.r_type} {r.target.type}:{renamed(r.target.type, r.target.value)}"
                for r in observable.relationships
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
            # ace3's Analysis.error (2b9fcd2c), on a result whose module failed and on no other, as
            # ace4's form holds a result's error (ace_core::normal). A tool or a library names the
            # file by the path ace3 gave it, on its node; the port writes the path in the alert, so
            # the node's directory is taken off the front of it here and nothing else is changed
            if getattr(analysis, "error", None):
                result["error"] = analysis.error
                if observable.type == "file" and observable.file_path:
                    files_dir = observable.full_path.removesuffix("/" + observable.file_path)
                    result["error"] = result["error"].replace(files_dir + "/", "")
                # when the module raised, ace3's engine ends the reason with its crash report's id,
                # which is new each run, like the fields TREE_RUN_FIELDS names: it's left out here
                # and of the summary, which often repeats the reason
                result["error"] = CRASH_ID.sub("", result["error"])
                if isinstance(result["summary"], str):
                    result["summary"] = CRASH_ID.sub("", result["summary"])
            for path in TREE_RUN_FIELDS.get(class_name, []):
                remove_at(result, path.split("/"))
            if class_name == "YaraScanResults_v3_4":
                exported_rule_dates(result)
            # ace3 writes this with json.dumps' spaces and ace4 with serde_json, so it's compared
            # as the same compact text, which any change to its content still shows
            raw = result["details"].get("rdap_raw_json") if class_name == "RdapAnalysis" else None
            if isinstance(raw, str):
                result["details"]["rdap_raw_json"] = json.dumps(json.loads(raw), separators=(",", ":"), ensure_ascii=False)
            if class_name == "RTFOLEObjectAnalysis":
                rtfole_in_alert_paths(result, observable.full_path.removesuffix("/" + observable.file_path))
            if class_name == "MSOfficeEncryptionAnalysis":
                msoffice_in_alert_paths(result, observable.full_path.removesuffix("/" + observable.file_path))
            if class_name == "ObservableModifierAnalysis":
                modifier_modules(result["details"])
            entry["results"][tree_module(analysis)] = renamed_strings(result, renames)
        for detection in detections:
            entry["detections"].setdefault(detection.description, []).append(json_safe(detection.details))
        for details in entry["detections"].values():
            details.sort(key=lambda d: json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
        if observable.time is not None:
            entry["time"] = tree_time(observable.time)
        if observable.redirection is not None:
            entry["redirection"] = (
                f"{observable.redirection.type}:{renamed(observable.redirection.type, observable.redirection.value)}"
            )
        if observable.type == "file":
            entry["paths"] = {observable.file_path: members(sorted(observable.yara_meta_tags))}
        value = renamed(observable.type, observable.value)
        if observable.type == "file" and os.path.dirname(observable.file_path).endswith(".xlmdeobfuscator"):
            if observable.file_name in ("xlmdeobfuscator.stdout", "xlmdeobfuscatorextractcells.stdout"):
                value = xlm_output_value(observable, observable.full_path.removesuffix("/" + observable.file_path))
        key = f"{observable.type}:{value}"
        if key in observables:
            merge_tree_entry(observables[key], entry)
        else:
            observables[key] = entry
    form = {"form": 1, "observables": observables}
    # a detection on the root itself, as configuration_defined_tagging adds
    if root.detections:
        on_root = {}
        for detection in root.detections:
            on_root.setdefault(detection.description, []).append(json_safe(detection.details))
        for details in on_root.values():
            details.sort(key=lambda d: json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
        form["root"] = {"detections": on_root}
    return form


# the bodies the lure module reads, HTML and plain text, which ace3 doesn't read past this
TREE_VIEW_BODY_MARKERS = (".unknown_text_html", ".unknown_text_plain")
TREE_VIEW_BODY_MAX = 5 * 1024 * 1024


def tree_view(root):
    """The whole root in the shape of ace4's `ace_sdk::tree::TreeView`, which the core hands a module
    that walks it: its observables, one per (type, value), a file's with each path and that path's
    yara_meta types, and every analysis with what it added, by index. ace3 has a file observable per
    path, so a file's analyses are those of each of its observables; ace4 analyzes a file once, so of
    two analyses by one class of one file only the first is kept. Each result keeps its class, its
    module as the trees name it, its summary and its details, for a test to compare with, and the
    bodies the lure module reads, HTML and plain text, are kept as base64, by sha256."""
    import base64

    observables, index, results, bodies = [], {}, [], {}

    def observable_index(observable):
        key = (observable.type, observable.value)
        if key not in index:
            index[key] = len(observables)
            observables.append({
                "type": observable.type,
                "value": observable.value,
                "tags": [],
                "directives": [],
                "detections": [],
                "paths": [],
            })
        entry = observables[index[key]]
        for tag in sorted(str(t) for t in observable.tags):
            if tag not in entry["tags"]:
                entry["tags"].append(tag)
        for directive in sorted(d for d in observable.directives if not d.startswith("yara_meta:")):
            if directive not in entry["directives"]:
                entry["directives"].append(directive)
        for detection in observable.detections:
            if detection.description not in entry["detections"]:
                entry["detections"].append(detection.description)
        if observable.type == "file":
            entry["size"] = observable.size
            if not any(p["path"] == observable.file_path for p in entry["paths"]):
                entry["paths"].append({"path": observable.file_path, "yara_meta": sorted(observable.yara_meta_tags)})
            name = observable.file_name or ""
            if any(m in name for m in TREE_VIEW_BODY_MARKERS) and observable.size <= TREE_VIEW_BODY_MAX:
                with open(observable.full_path, "rb") as fp:
                    bodies[observable.value] = base64.b64encode(fp.read()).decode()
        return index[key]

    for observable in root.all_observables:
        observable_index(observable)
    seen = set()
    for observable in root.all_observables:
        for analysis in observable.all_analysis:
            if not analysis:
                continue
            analysis.load_details()
            class_name = type(analysis).__name__
            on = observable_index(observable)
            if (on, tree_module(analysis)) in seen:
                continue
            seen.add((on, tree_module(analysis)))
            results.append({
                "observable": on,
                "class": class_name,
                "module": tree_module(analysis),
                "tags": sorted(str(tag) for tag in analysis.tags),
                "summary": analysis.summary,
                "details": json_safe(analysis.details),
                # ace3's Analysis.error, kept only when the module failed (ace_sdk's TreeResult::error)
                **({"error": analysis.error} if getattr(analysis, "error", None) else {}),
                "added": [
                    {"observable": observable_index(o)} | ({"path": o.file_path} if o.type == "file" else {})
                    for o in analysis.observables
                ],
            })
    return {
        "alert_type": root.alert_type,
        "observables": observables,
        "results": results,
        "bodies": bodies,
    }


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


def deterministic_id_copy(copy_path, source_path, password):
    """The sha256 of pdf_encryption_analyzer's decrypted copy as the port writes it, or None. pikepdf's
    save() makes the copy's second /ID from the clock, so its sha256 is new each run; the port makes
    it from the content, as save(deterministic_id=True) does. That save is made here from the same
    file and password, and its sha256 is kept only if ace3's copy is the same bytes once its second
    /ID is that save's: so any other byte that differs shows as a different sha256."""
    import io
    import re

    import pikepdf

    with open(copy_path, "rb") as fp:
        written = fp.read()
    with pikepdf.open(source_path, password=password) as pdf:
        out = io.BytesIO()
        pdf.save(out, deterministic_id=True)
    deterministic = out.getvalue()
    pattern = rb"/ID\s*\[\s*<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*\]"
    ours, theirs = re.findall(pattern, written), re.findall(pattern, deterministic)
    if not ours or not theirs:
        return None
    if written.replace(ours[-1][1], theirs[-1][1]) != deterministic:
        return None
    return hashlib.sha256(deterministic).hexdigest()


def deterministic_id_renames(root):
    """Value to the value it has when pdf_encryption_analyzer's copies have the port's /ID
    (deterministic_id_copy): each copy's sha256, md5 and sha1, and those of the files made from a
    copy that hold its second /ID, such as pdf_analyzer's dump of it, with that /ID swapped too.
    And each of pdf-parser.py's dumps, by what it is with the port's Python in its first line
    (port_python_dump)."""
    import io
    import re

    import pikepdf

    renames = {}

    def rename_bytes(old, new):
        for kind in ("md5", "sha1", "sha256"):
            renames[hashlib.new(kind, old).hexdigest()] = hashlib.new(kind, new).hexdigest()

    pattern = rb"/ID\s*\[\s*<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*\]"
    for analysis in root.all_analysis:
        if type(analysis).__name__ != "PDFEncryptionAnalysis":
            continue
        analysis.load_details()
        for copy in analysis.observables:
            if copy.type != "file":
                continue
            if deterministic_id_copy(copy.full_path, analysis.observable.full_path, analysis.details["password"]) is None:
                continue
            with open(copy.full_path, "rb") as fp:
                written = fp.read()
            with pikepdf.open(analysis.observable.full_path, password=analysis.details["password"]) as pdf:
                out = io.BytesIO()
                pdf.save(out, deterministic_id=True)
            rename_bytes(written, out.getvalue())
            old_id = re.findall(pattern, written)[-1][1]
            new_id = re.findall(pattern, out.getvalue())[-1][1]
            for other in root.all_observables:
                if other.type != "file" or not other.file_path.startswith(copy.file_path + "."):
                    continue
                with open(other.full_path, "rb") as fp:
                    data = fp.read()
                swapped = data
                for old, new in ((old_id, new_id), (old_id.lower(), new_id.lower()), (old_id.upper(), new_id.upper())):
                    swapped = swapped.replace(old, new)
                if other.file_path.endswith(".pdfparser"):
                    swapped = port_python_dump(swapped)
                if swapped != data:
                    rename_bytes(data, swapped)
    # pdf-parser.py's dumps, whose first line names the Python it ran on (PORT_PYTHON)
    for other in root.all_observables:
        if other.type != "file" or not other.file_path.endswith(".pdfparser") or other.value in renames:
            continue
        with open(other.full_path, "rb") as fp:
            data = fp.read()
        if port_python_dump(data) != data:
            rename_bytes(data, port_python_dump(data))
    return renames


def renamed_strings(value, renames):
    """value with every string that is a renamed hash replaced, as results hold them."""
    if isinstance(value, str):
        return renames.get(value, value)
    if isinstance(value, list):
        return [renamed_strings(v, renames) for v in value]
    if isinstance(value, dict):
        return {k: renamed_strings(v, renames) for k, v in value.items()}
    return value


def dump_analysis(analysis):
    analysis.load_details()
    # a module's summary details, kept only when it has some, so dumps made before stay as they were
    summary_details = [
        {"header": d.header, "content": d.content, "format": d.format}
        for d in getattr(analysis, "summary_details", None) or []
    ]
    # ace3's Analysis.error (2b9fcd2c), kept only when the module failed, so dumps made before it, and
    # of modules that didn't fail, stay as they were
    error = getattr(analysis, "error", None)
    return ({"summary_details": summary_details} if summary_details else {}) | (
        {"error": error} if error else {}
    ) | {
        "module_path": analysis.module_path,
        "class": type(analysis).__name__,
        "summary": analysis.summary,
        "details": json_safe(analysis.details),
        "tags": sorted(str(tag) for tag in analysis.tags),
        "detections": [
            {"description": d.description, "details": json_safe(d.details)} for d in analysis.detections
        ],
        "observables": [dump_observable(o) for o in analysis.observables],
    } | (
        # one class configured as several instances, such as ace3's PcapCategoryAnalyzer
        {"instance": analysis.instance} if getattr(analysis, "instance", None) else {}
    ) | (
        {
            "deterministic_id_sha256": {
                o.file_path: deterministic_id_copy(o.full_path, analysis.observable.full_path, analysis.details["password"])
                for o in analysis.observables
                if o.type == "file"
            }
        }
        if type(analysis).__name__ == "PDFEncryptionAnalysis"
        else {}
    )


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
    if args.dns:
        point_dns(args.dns)
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

    if args.snort_rules:
        fake_snort_index(args.snort_rules)
    if args.brocess:
        fake_brocess(args.brocess)
    store = fake_brocess_store(args.brocess_store) if args.brocess_store else None
    if args.encryption_key:
        use_encryption_key(args.encryption_key)
    if args.observable_tags:
        fake_observable_tags(args.observable_tags)
    if args.detections:
        fake_detections(args.detections)
    email_archive = fake_email_archive(args.email_archive_store, work) if args.email_archive_store else None
    email_archive_before = json.loads(json.dumps(email_archive.rows())) if email_archive else None
    before = json.loads(json.dumps(store.rows())) if store else None
    fluent_bit = record_fluent_bit() if args.fluent_bit else None
    scanner_requests = []
    if args.scanner_output:
        fake_scanners(args.scanner_output, scanner_requests)

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
        if args.export_detections:
            if not args.detections:
                raise SystemExit("--export-detections needs --detections")
            export_detections(args.detections)
    elif args.export_detections:
        raise SystemExit("--export-detections needs --yara-rules")

    root_dir = os.path.join(work, "root")
    root = RootAnalysis(uuid=str(uuid.uuid4()), storage_dir=root_dir)
    root.initialize_storage()
    root.tool = "ACE - Command Line Analysis"
    root.tool_instance = socket.gethostname()
    root.alert_type = args.alert_type
    root.analysis_mode = args.analysis_mode
    get_config().get_analysis_mode_config(root.analysis_mode).cleanup = False
    root.description = "ace4 reference dump"
    root.set_event_time(datetime.datetime.now(), EventTimeSource.NOW)
    root.details = {"comment": "ace4 reference dump"}

    source = None
    if args.extracted_from:
        source = root.add_file_observable(args.extracted_from[0], target_path=args.extracted_from[1])
        for tag in args.source_tag:
            source.add_tag(tag)
    if args.file and args.added_by:
        import importlib

        module_name, class_name = args.added_by.split(":")
        adder = getattr(importlib.import_module(module_name), class_name)()
        source.add_analysis(adder)
        observable = adder.add_file_observable(args.file, target_path=args.alert_path)
    elif args.carrying_email:
        email_path = carrying_email(work, args.carrying_email, args.file, os.path.basename(args.alert_path))
        observable = root.add_file_observable(email_path, target_path="email.rfc822")
    elif args.file:
        observable = root.add_file_observable(args.file, target_path=args.alert_path)
    if args.file:
        for tag in [] if args.carrying_email else args.meta_tag:
            name, value = tag.split("=", 1)
            observable.add_yara_meta(name, value)
    else:
        observable = root.add_observable_by_spec(args.observable[0], args.observable[1])
    if observable is None:
        sys.exit("ace3 refused the observable")
    for directive in args.directive:
        observable.add_directive(directive)
    for tag in args.tag:
        observable.add_tag(tag)
    if source is not None:
        from saq.constants import R_EXTRACTED_FROM

        observable.add_relationship(R_EXTRACTED_FROM, source)
    for kind, other_type, other_value in args.relationship:
        other = root.add_observable_by_spec(other_type, other_value)
        if other is None:
            sys.exit("ace3 refused the related observable")
        observable.add_relationship(kind, other)
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
        engine.configuration_manager.enable_module(name, args.analysis_mode)

    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = RootAnalysis(storage_dir=root_dir)
    root.load()
    target = root.get_observable(target_uuid)
    carried = None
    if args.carrying_email:
        target = next(o for o in root.all_observables if o.type == "file" and o.file_path == args.alert_path)
        carried = carrying_email_body(root, target)
    dumped_file = None
    if args.dump_file:
        dumped_file = next((o for o in root.all_observables if o.type == "file" and o.file_path == args.dump_file), None)
        target = dumped_file or target

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
        }
        | ({"tags": args.tag} if args.tag else {})
        | ({"carrying_email": carried} if args.carrying_email else {})
        | (
            {"relationships": [{"type": k, "target": {"type": t, "value": v}} for k, t, v in args.relationship]}
            if args.relationship
            else {}
        )
        | (
            {
                "extracted_from": {
                    "file_path": source.file_path,
                    "value": source.value,
                    "tags": sorted(str(tag) for tag in source.tags),
                }
                | ({"added_by": args.added_by} if args.added_by else {})
            }
            if source is not None
            else {}
        ),
        "observable_after": dump_observable(target),
        "analyses": [dump_analysis(a) for a in target.all_analysis],
    }
    if dumped_file is not None:
        # what the module that added the file gave it, which was there before this module ran
        dump["input"]["meta_tags"] = dump["observable_after"]["yara_meta"]
        dump["input"]["tags"] = dump["observable_after"]["tags"]
        dump["input"]["dump_file"] = args.dump_file
    if args.sidecars and target.type == "file":
        files_root = target.full_path[: -len(target.file_path)].rstrip("/")
        sidecars = {}
        for directory, _, names in os.walk(files_root):
            for name in names:
                if name.endswith(args.sidecars):
                    path = os.path.join(directory, name)
                    with open(path, encoding="utf-8") as fp:
                        sidecars[os.path.relpath(path, files_root)] = fp.read()
        dump["sidecars"] = sidecars
    if store is not None:
        dump["brocess_before"] = before
        dump["brocess_after"] = store.rows()
        dump["brocess_reads"] = store.reads
    if fluent_bit is not None:
        dump["fluent_bit"] = fluent_bit
    if args.scanner_output:
        # the request for the dumped file, when the run asked for others too
        name = os.path.basename(target.file_path) if target.type == "file" else None
        mine = [r for r in scanner_requests if r.get("file_name", r.get("target")) == name]
        dump["scanner_request"] = (mine or scanner_requests or [None])[-1]
    if email_archive is not None:
        dump["email_archive_before"] = email_archive_before
        dump["email_archive_after"] = email_archive.rows()
        dump["email_archive_reads"] = email_archive.reads
    if args.tree_view:
        dump["tree_view"] = tree_view(root)
        dump["root_after"] = {"description": root.description, "details": json_safe(root.details)}
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
