"""A fake Splunk REST API for the Splunk module's reference dumps (PLAN.md 1.24 and 1.28).

There is no Splunk on this laptop. This server answers the calls ace3's Splunk client makes through
splunk-sdk (saq/splunk.py) the way splunkd's management API does, from rows in a fixture file, and
records every exchange so ace4's port can replay them:

    POST   /services/auth/login                   a session key, as XML, and its cookie
    GET    /services/server/info                  an Atom feed whose version (9.3.2) selects the v2
                                                  search API
    POST   /services/search/v2/jobs               a new search job: <response><sid>...</sid></response>
    GET    /services/search/v2/jobs/<sid>         the job as an Atom entry: dispatchState, isDone,
                                                  doneProgress, isFailed, eventCount, runDuration
    POST   /services/search/v2/jobs/<sid>/results the results with output_mode=json, once the job is
                                                  done; 204 before
    DELETE /services/search/v2/jobs/<sid>         removes the job
    POST   /services/search/v2/jobs/<sid>/control action=cancel

Paths may also come under /servicesNS/<owner>/<app>/, and the v1 search/jobs paths work too. Every
call but the login needs the session, by cookie or by an Authorization: Splunk header.

A job reports RUNNING for the first --running-polls status reads and DONE after them; with
--never-done it never finishes. Its results are the fixture's rows for the hostname quoted in the
search, or for an entry whose `match` strings the search all has. The rows are made up (see the fixture's "about").

It leaves out most of splunkd: there's no search language (a search matches rows by the quoted
hostname alone), time ranges, max_count, count and offset are ignored, a job is never QUEUED,
PARSING, FAILED or paused, results come back whole with no preview or paging, the only output
mode is json, and there is no token authentication, export or oneshot search. It always says
it's version 9.3.2, so splunk-sdk always takes the v2 search API.

It speaks HTTPS with a self-signed certificate, because splunk-sdk talks HTTPS to splunkd, and it
uses only Python's standard library, so it runs in ace3's dev container:

    python3 -I fake_splunk.py --rows rows.json --cert cert.pem --key key.pem --port 8089 \\
        --record DIR --pid-file DIR/pid [--running-polls 4 | --never-done]

It writes DIR/http.json and one DIR/NNN-<sha256 prefix>.body per response, in the shape
run_module.py records RDAP's exchanges in, plus each request's body. The password in a login
request is replaced with <redacted>.
"""

import argparse
import hashlib
import http.server
import json
import os
import re
import ssl
import sys
import threading
import urllib.parse
from datetime import datetime, timezone

SPLUNK_VERSION = "9.3.2"
SESSION_KEY = "ace4-fake-session-0000000000000000"
COOKIE_NAME = "splunkd_8089"
# job ids look like splunkd's: an epoch time, a dot and a counter
SID_BASE = "1767225600"
ATOM = "http://www.w3.org/2005/Atom"
REST = "http://dev.splunk.com/ns/rest"


def xml_escape(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def s_dict(items, indent="      "):
    """An s:dict of string values, or nested dicts and lists, as splunkd writes them."""
    lines = [f"{indent}<s:dict>"]
    for key, value in items.items():
        if isinstance(value, dict):
            lines.append(f'{indent}  <s:key name="{xml_escape(key)}">')
            lines.append(s_dict(value, indent + "    "))
            lines.append(f"{indent}  </s:key>")
        elif isinstance(value, list):
            lines.append(f'{indent}  <s:key name="{xml_escape(key)}"><s:list>'
                         + "".join(f"<s:item>{xml_escape(v)}</s:item>" for v in value)
                         + "</s:list></s:key>")
        else:
            lines.append(f'{indent}  <s:key name="{xml_escape(key)}">{xml_escape(value)}</s:key>')
    lines.append(f"{indent}</s:dict>")
    return "\n".join(lines)


def now_text():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


class Job:
    def __init__(self, sid, search, running_polls):
        self.sid = sid
        self.search = search
        self.running_polls = running_polls
        self.status_reads = 0
        self.deleted = False

    @property
    def done(self):
        return self.running_polls is not None and self.status_reads > self.running_polls


class FakeSplunk:
    def __init__(self, rows, running_polls, record_dir, any_hostname=False):
        self.rows = rows
        self.any_hostname = any_hostname
        self.running_polls = running_polls
        self.record_dir = record_dir
        self.jobs = {}
        self.exchanges = []
        self.lock = threading.Lock()

    def rows_for(self, search):
        """The fixture rows for the hostname the search quotes, or of the first entry whose `match`
        strings are all in the search."""
        for entry in self.rows["searches"]:
            if self.any_hostname:
                return entry["rows"]
            if "hostname" in entry and f'hostname="{entry["hostname"]}"' in search:
                return entry["rows"]
            if "match" in entry and all(m in search for m in entry["match"]):
                return entry["rows"]
        return []

    def record(self, entry, body):
        with self.lock:
            index = len(self.exchanges)
            entry["body_size"] = len(body)
            entry["body_sha256"] = hashlib.sha256(body).hexdigest()
            name = f"{index:03d}-{entry['body_sha256'][:12]}.body"
            with open(os.path.join(self.record_dir, name), "wb") as fp:
                fp.write(body)
            entry["body_file"] = name
            self.exchanges.append(entry)
            with open(os.path.join(self.record_dir, "http.json"), "w") as fp:
                json.dump({
                    "about": "Every request ace3's Splunk client made to tools/ace3/dumps/fake_splunk.py, "
                             "in order, with the fake's response. Each body_file holds the response body. "
                             "request_body is the form the client sent, with a login's password redacted.",
                    "exchanges": self.exchanges,
                }, fp, indent=2, sort_keys=True)


def make_handler(fake, port):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def version_string(self):
            return "Splunkd"

        def log_message(self, format, *args):
            sys.stderr.write("fake splunk: " + (format % args) + "\n")

        def _read_form(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            text = raw.decode("utf-8", "replace")
            return text, urllib.parse.parse_qs(text, keep_blank_values=True)

        def _respond(self, method, status, body, content_type, request_body, extra_headers=()):
            if isinstance(body, str):
                body = body.encode("utf-8")
            headers = {"Content-Type": content_type, "Content-Length": str(len(body)),
                       "Connection": "Close", "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                       "X-Content-Type-Options": "nosniff"}
            headers.update(dict(extra_headers))
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)
            request_headers = {k: v for k, v in self.headers.items()
                               if k.lower() not in ("authorization", "cookie")}
            fake.record({
                "method": method,
                "url": f"https://127.0.0.1:{port}{self.path}",
                "request_headers": request_headers,
                "request_body": request_body,
                "status": status,
                "response_headers": headers,
            }, body)

        def _messages(self, method, status, kind, text, request_body):
            body = ('<?xml version="1.0" encoding="UTF-8"?>\n<response>\n  <messages>\n'
                    f'    <msg type="{kind}">{xml_escape(text)}</msg>\n  </messages>\n</response>\n')
            self._respond(method, status, body, "text/xml; charset=UTF-8", request_body)

        def _authenticated(self):
            if self.headers.get("Authorization", "") == f"Splunk {SESSION_KEY}":
                return True
            return f"{COOKIE_NAME}={SESSION_KEY}" in self.headers.get("Cookie", "")

        def _route(self):
            """The path after /services/ or /servicesNS/<owner>/<app>/, and the query."""
            parsed = urllib.parse.urlsplit(self.path)
            path = urllib.parse.unquote(parsed.path)
            m = re.match(r"^/servicesNS/[^/]+/[^/]+/(.*)$", path) or re.match(r"^/services/(.*)$", path)
            route = m.group(1) if m else None
            return route, urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        def _handle(self, method):
            request_text, form = self._read_form() if method in ("POST", "DELETE") else ("", {})
            route, query = self._route()
            if route is None:
                return self._messages(method, 404, "ERROR", "Not Found", request_text)

            if route == "auth/login" and method == "POST":
                user, password = form.get("username", [""])[0], form.get("password", [""])[0]
                redacted = urllib.parse.urlencode(
                    [(k, "<redacted>" if k == "password" else v) for k, vs in form.items() for v in vs])
                if not user or not password:
                    return self._messages(method, 401, "WARN", "Login failed", redacted)
                body = ('<response>\n  <sessionKey>' + SESSION_KEY + '</sessionKey>\n'
                        '  <messages>\n    <msg code=""></msg>\n  </messages>\n</response>\n')
                cookie = f"{COOKIE_NAME}={SESSION_KEY}; Path=/; Secure; HttpOnly; Max-Age=3600"
                return self._respond(method, 200, body, "text/xml; charset=UTF-8", redacted,
                                     [("Set-Cookie", cookie)])

            if not self._authenticated():
                return self._messages(method, 401, "WARN", "call not properly authenticated", request_text)

            if route == "server/info" and method == "GET":
                updated = now_text()
                content = s_dict({"build": "ace4fake", "serverName": "fake-splunk", "product_type": "enterprise",
                                  "version": SPLUNK_VERSION})
                body = (f'<?xml version="1.0" encoding="UTF-8"?>\n'
                        f'<feed xmlns="{ATOM}" xmlns:s="{REST}" xmlns:opensearch="http://a9.com/-/spec/opensearch/1.1/">\n'
                        f'  <title>server-info</title>\n  <id>https://127.0.0.1:{port}/services/server/info</id>\n'
                        f'  <updated>{updated}</updated>\n  <generator build="ace4fake" version="{SPLUNK_VERSION}"/>\n'
                        f'  <author>\n    <name>Splunk</name>\n  </author>\n'
                        f'  <opensearch:totalResults>1</opensearch:totalResults>\n'
                        f'  <opensearch:itemsPerPage>30</opensearch:itemsPerPage>\n'
                        f'  <opensearch:startIndex>0</opensearch:startIndex>\n  <s:messages/>\n'
                        f'  <entry>\n    <title>server-info</title>\n'
                        f'    <id>https://127.0.0.1:{port}/services/server/info/server-info</id>\n'
                        f'    <updated>{updated}</updated>\n'
                        f'    <link href="/services/server/info/server-info" rel="alternate"/>\n'
                        f'    <author>\n      <name>system</name>\n    </author>\n'
                        f'    <content type="text/xml">\n{content}\n    </content>\n  </entry>\n</feed>\n')
                return self._respond(method, 200, body, "text/xml; charset=UTF-8", request_text)

            m = re.match(r"^search/(?:v2/)?jobs/?$", route)
            if m and method == "POST":
                search = form.get("search", [""])[0]
                if not search:
                    return self._messages(method, 400, "FATAL", "Empty search.", request_text)
                with fake.lock:
                    sid = f"{SID_BASE}.{len(fake.jobs) + 1}"
                    fake.jobs[sid] = Job(sid, search, fake.running_polls)
                body = f'<?xml version="1.0" encoding="UTF-8"?>\n<response>\n  <sid>{sid}</sid>\n</response>\n'
                return self._respond(method, 201, body, "text/xml; charset=UTF-8", request_text)

            # splunk-sdk deletes a job at its path with a trailing slash, which splunkd accepts
            m = re.match(r"^search/(?:v2/)?jobs/([^/]+)(?:/([a-z_]+))?/?$", route)
            if m:
                sid, action = m.group(1), m.group(2)
                job = fake.jobs.get(sid)
                if job is None or job.deleted:
                    return self._messages(method, 404, "FATAL", "Unknown sid.", request_text)

                if action is None and method == "GET":
                    job.status_reads += 1
                    rows = fake.rows_for(job.search)
                    done = job.done
                    progress = 1.0 if done else round(job.status_reads / ((job.running_polls or 4) + 2), 2)
                    content = {
                        "cursorTime": "1970-01-01T00:00:00.000+00:00",
                        "dispatchState": "DONE" if done else "RUNNING",
                        "doneProgress": f"{progress}",
                        "eai:acl": {"app": "search", "can_write": "1", "modifiable": "1",
                                    "owner": "ace4", "perms": {"read": ["ace4"], "write": ["ace4"]},
                                    "sharing": "global", "ttl": "600"},
                        "eventCount": str(len(rows) if done else 0),
                        "isDone": "1" if done else "0",
                        "isFailed": "0",
                        "isFinalized": "0",
                        "isPaused": "0",
                        "label": "",
                        "resultCount": str(len(rows) if done else 0),
                        "runDuration": f"{0.25 * job.status_reads:.3f}",
                        "sid": sid,
                    }
                    updated = now_text()
                    links = "".join(
                        f'  <link href="/servicesNS/ace4/search/search/v2/jobs/{sid}/{rel}" rel="{rel}"/>\n'
                        for rel in ("events", "results", "results_preview", "summary", "timeline", "control"))
                    body = (f'<?xml version="1.0" encoding="UTF-8"?>\n'
                            f'<entry xmlns="{ATOM}" xmlns:s="{REST}" xmlns:opensearch="http://a9.com/-/spec/opensearch/1.1/">\n'
                            f'  <title>{xml_escape(job.search)}</title>\n'
                            f'  <id>https://127.0.0.1:{port}/services/search/v2/jobs/{sid}</id>\n'
                            f'  <updated>{updated}</updated>\n'
                            f'  <link href="/servicesNS/ace4/search/search/v2/jobs/{sid}" rel="alternate"/>\n'
                            f'  <published>{updated}</published>\n{links}'
                            f'  <author>\n    <name>ace4</name>\n  </author>\n'
                            f'  <content type="text/xml">\n{s_dict(content, "    ")}\n  </content>\n</entry>\n')
                    return self._respond(method, 200, body, "text/xml; charset=UTF-8", request_text)

                if action == "results" and method in ("GET", "POST"):
                    params = form if method == "POST" else query
                    if not job.done:
                        return self._respond(method, 204, b"", "text/xml; charset=UTF-8", request_text)
                    if params.get("output_mode", [""])[0] != "json":
                        return self._messages(method, 400, "FATAL", "the fake answers output_mode=json only",
                                              request_text)
                    rows = fake.rows_for(job.search)
                    fields = []
                    for row in rows:
                        for name in row:
                            if name not in fields:
                                fields.append(name)
                    body = json.dumps({"preview": False, "init_offset": 0, "messages": [],
                                       "fields": [{"name": name} for name in fields],
                                       "results": rows, "highlighted": {}}, separators=(",", ":"))
                    return self._respond(method, 200, body + "\n", "application/json; charset=UTF-8", request_text)

                if action is None and method == "DELETE":
                    job.deleted = True
                    return self._messages(method, 200, "INFO", "Search job cancelled.", request_text)

                if action == "control" and method == "POST":
                    job.deleted = form.get("action", [""])[0] == "cancel" or job.deleted
                    return self._messages(method, 200, "INFO", "Search job cancelled.", request_text)

            return self._messages(method, 404, "ERROR", f"Not Found: {route}", request_text)

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def do_DELETE(self):
            self._handle("DELETE")

    return Handler


def main():
    parser = argparse.ArgumentParser(prog="fake_splunk.py")
    parser.add_argument("--rows", required=True, help="the fixture of made-up rows")
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--record", required=True, help="directory for http.json and the bodies")
    parser.add_argument("--port", type=int, default=8089, help="the port on 127.0.0.1, 8089 as splunkd's")
    parser.add_argument("--any-hostname", action="store_true", help="every search gets the first rows, as a replayed recording does")
    parser.add_argument("--pid-file", required=True, help="written with the process id once the server listens")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--running-polls", type=int, help="status reads that report RUNNING before DONE")
    group.add_argument("--never-done", action="store_true", help="jobs stay RUNNING")
    args = parser.parse_args()

    with open(args.rows) as fp:
        rows = json.load(fp)
    os.makedirs(args.record, exist_ok=True)
    fake = FakeSplunk(rows, None if args.never_done else args.running_polls, args.record, args.any_hostname)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(fake, args.port))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    with open(args.pid_file + ".tmp", "w") as fp:
        fp.write(str(os.getpid()))
    os.rename(args.pid_file + ".tmp", args.pid_file)
    server.serve_forever()


if __name__ == "__main__":
    main()
