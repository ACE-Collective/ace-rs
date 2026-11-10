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
- with --sidecars SUFFIX, the dump keeps the text of each file the run left in the root's file
  directory whose name ends in SUFFIX, by its path there, such as the DOM snapshots ace3's HTML
  modules write beside the scripts they extract, which aren't observables;
- with --extracted-from FILE ALERT_PATH, the root also holds that file, the observable is
  extracted_from it, and --source-tag tags it, as a document file_type called microsoft_office;
- with --added-by MODULE:CLASS, the observable is added by an analysis of that class on the
  --extracted-from file rather than by the root, such as an output of OfficeParserAnalysis3;
- with --tag TAG, the observable carries that tag, as the module that added it would give it, such as
  rtfole's extracted_rtf; the dump's input lists it;
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
    parser.add_argument("--tree", action="store_true", help="also write the root in the normal form to tree.json")
    parser.add_argument(
        "--sidecars", metavar="SUFFIX",
        help="keep the text of each file the run wrote under the root whose name ends in SUFFIX, such as .dom.json",
    )
    parser.add_argument("--label", default="", help="a name for the input, written into the dump")
    args = parser.parse_args(sys.argv[1:])
    if bool(args.file) == bool(args.observable):
        parser.error("give exactly one of --file and --observable")
    if args.added_by and not args.extracted_from:
        parser.error("--added-by needs --extracted-from")
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
    "EmailAddressFQDNAnalysis": "email_address_fqdn_analyzer",
    "ProtectedURLAnalysis": "protected_url_analyzer",
    "HTMLDataURLAnalysis": "html_data_url_extraction",
    "HARAnalysis": "har_extraction",
    "HTMLJavaScriptExtractionAnalysis": "html_js_extraction",
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
    "NRDAnalysis": ["details/matched_at"],
}
# ace3's excluded_analysis holds `module:<class ...>` strings
TREE_EXCLUDED = {
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
    "ExifAnalyzer": "exif",
    "QRCodeAnalyzer": "qrcode",
    "XLMMacroDeobfuscatorAnalyzer": "xlmdeobfuscator",
    "YaraScanner_v3_4": "yara_scanner_v3_4",
    "URLExtractionAnalyzer": "url_extraction",
    "IOCExtractionAnalyzer": "ioc_extraction",
    "IDNAAnalyzer": "idna_analyzer",
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
    # a module's summary details, kept only when it has some, so dumps made before stay as they were
    summary_details = [
        {"header": d.header, "content": d.content, "format": d.format}
        for d in getattr(analysis, "summary_details", None) or []
    ]
    return ({"summary_details": summary_details} if summary_details else {}) | {
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
    before = json.loads(json.dumps(store.rows())) if store else None
    fluent_bit = record_fluent_bit() if args.fluent_bit else None

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
    elif args.file:
        observable = root.add_file_observable(args.file, target_path=args.alert_path)
    if args.file:
        for tag in args.meta_tag:
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
        }
        | ({"tags": args.tag} if args.tag else {})
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
