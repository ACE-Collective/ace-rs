"""What ace3's newly registered domains code does with tools/ace3/dumps/fixtures/nrd (PLAN.md 7.4).

It runs inside ace3's dev container on ace3's Python, as run_module.py does, with everything it
writes under its work directory in /tmp:

    docker exec -i -e PYTHONDONTWRITEBYTECODE=1 -e SAQ_SKIP_LOCAL_SAQ_YAML=1 ace-dev-1 \\
        /venv/bin/python3 - --work /tmp/ace-rs-dumps/runs/nrd --fixtures /tmp/ace-rs-dumps/fixtures/nrd \\
        --out /tmp/ace-rs-dumps/runs/nrd/reference.json < tools/ace3/dumps/nrd_reference.py

It writes three things to --out, which make-dumps keeps as tools/ace3/dumps/reference/nrd/:

- `lookups`: for each value in fixtures/nrd/lookups.json, what saq.nrd.util makes of it: the
  normalized name (`_normalize`), the names it looks up (`_candidate_domains`) and the registrable
  domain the analyzer asks RDAP about (`registrable_domain`);
- `lines`: for each line of the lists, what saq.nrd.refresh keeps of it (`_normalize_domain`);
- `refresh`: `refresh()` run through the steps below against a list server started here, with each
  step's exit code, every request it made, and the database it left: its meta rows but the time,
  and its domains.

The steps: a first refresh with no database; a second at once, inside check_interval_hours; a
third after the interval has passed, whose HEAD requests match; a fourth after the first list
changed upstream; a fifth with a list whose primary URL fails, from its backup; and a sixth whose
only list fails everywhere, which leaves the fifth's database.

With --db PATH it also copies the first step's database there, for the analyzer's dumps.
"""

import argparse
import http.server
import json
import os
import shutil
import sqlite3
import sys
import threading

ACE3 = "/opt/ace"
# the list server's port, fixed so the configured URLs, and the hash ace3 keeps of them, are too
LIST_PORT = 8091

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


class Lists:
    """What the list server serves: each path's file, ETag and Last-Modified, and the requests."""

    def __init__(self, fixtures):
        self.fixtures = fixtures
        self.files = {}
        self.requests = []
        self.lock = threading.Lock()

    def serve(self, path, file, etag, last_modified):
        with open(os.path.join(self.fixtures, "lists", file), "rb") as fp:
            self.files[path] = (fp.read(), etag, last_modified)

    def take_requests(self):
        with self.lock:
            taken, self.requests = self.requests, []
        return taken


def handler_for(lists):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def answer(self, body):
            with lists.lock:
                lists.requests.append([self.command, self.path])
            served = lists.files.get(self.path)
            if served is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            content, etag, last_modified = served
            self.send_response(200)
            # no charset, as some feeds serve them
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(content)))
            if etag:
                self.send_header("ETag", etag)
            if last_modified:
                self.send_header("Last-Modified", last_modified)
            self.end_headers()
            if body:
                self.wfile.write(content)

        def do_HEAD(self):
            self.answer(False)

        def do_GET(self):
            self.answer(True)

    return Handler


def database(path):
    """The database's meta rows, without the time, and its domains."""
    if not os.path.exists(path):
        return None
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
        domains = [row[0] for row in conn.execute("SELECT domain FROM nrd ORDER BY domain")]
    finally:
        conn.close()
    meta.pop("last_refreshed_at", None)
    meta["sources"] = json.loads(meta["sources"])
    meta["row_count"] = int(meta["row_count"])
    return {"meta": meta, "domains": domains}


def age_meta(path, hours):
    """Moves the database's last refresh back by `hours`."""
    from datetime import datetime, timedelta, timezone

    conn = sqlite3.connect(path)
    with conn:
        conn.execute(
            "UPDATE meta SET value = ? WHERE key = 'last_refreshed_at'",
            ((datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(),),
        )
    conn.close()


def main():
    parser = argparse.ArgumentParser(prog="nrd_reference.py")
    parser.add_argument("--work", required=True)
    parser.add_argument("--fixtures", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--db", help="where to copy the first refresh's database")
    args = parser.parse_args(sys.argv[1:])
    if not args.work.startswith("/tmp/"):
        parser.error("--work must be under /tmp")
    work = os.path.abspath(args.work)
    shutil.rmtree(work, ignore_errors=True)
    for sub in ("data", "tmp", "home"):
        os.makedirs(os.path.join(work, sub))
    os.environ["HOME"] = os.path.join(work, "home")
    os.environ["TLDEXTRACT_CACHE"] = os.path.join(work, "home", "tldextract")
    with open(os.path.join(work, "logging.yaml"), "w") as fp:
        fp.write(LOGGING_CONFIG)
    os.chdir(work)
    sys.path.insert(0, ACE3)

    from saq.environment import initialize_environment

    initialize_environment(
        saq_home=ACE3,
        data_dir=os.path.join(work, "data"),
        temp_dir=os.path.join(work, "tmp"),
        config_paths=[],
        logging_config_path=os.path.join(work, "logging.yaml"),
    )

    from saq.configuration import get_config
    from saq.configuration.schema import NRDURLList
    from saq.nrd import refresh as nrd_refresh
    from saq.nrd import util as nrd_util

    with open(os.path.join(args.fixtures, "lookups.json")) as fp:
        lookups = json.load(fp)["values"]
    lookup_results = []
    for value in lookups:
        normalized = nrd_util._normalize(value)
        lookup_results.append({
            "value": value,
            "normalized": normalized,
            "candidates": nrd_util._candidate_domains(normalized) if normalized else [],
            "registrable_domain": nrd_util.registrable_domain(value),
        })

    lines = []
    for name in sorted(n for n in os.listdir(os.path.join(args.fixtures, "lists")) if n.endswith(".txt")):
        with open(os.path.join(args.fixtures, "lists", name), "rb") as fp:
            text = fp.read().decode("utf-8")
        for line in text.splitlines():
            lines.append({"list": name, "line": line, "kept": nrd_refresh._normalize_domain(line)})

    lists = Lists(args.fixtures)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", LIST_PORT), handler_for(lists))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{LIST_PORT}"
    # no time between retries: ace3 sleeps a second, which changes nothing here
    nrd_refresh.time.sleep = lambda _seconds: None

    db_path = os.path.join(work, "nrd", "nrd_index.db")
    config = get_config().nrd
    config.enabled = True
    config.database_path = db_path
    config.check_interval_hours = 24

    def lists_config(entries):
        return [NRDURLList(url=f"{base}{path}", backups=[f"{base}{b}" for b in backups]) for path, backups in entries]

    steps = []

    def step(name, entries, before=None):
        config.url_lists = lists_config(entries)
        if before:
            before()
        code = nrd_refresh.refresh()
        steps.append({
            "step": name,
            "url_lists": [{"url": path, "backups": backups} for path, backups in entries],
            "exit_code": code,
            "requests": lists.take_requests(),
            "database": database(db_path),
        })

    lists.serve("/first.txt", "first.txt", '"first-1"', "Sat, 07 Nov 2026 10:00:00 GMT")
    lists.serve("/second.txt", "second.txt", None, "Sat, 07 Nov 2026 11:00:00 GMT")
    lists.serve("/backup.txt", "backup.txt", '"backup-1"', None)
    both = [("/first.txt", []), ("/second.txt", [])]
    step("no database", both)
    if args.db:
        os.makedirs(os.path.dirname(args.db), exist_ok=True)
        shutil.copyfile(db_path, args.db)
    step("inside the interval", both)
    step("after the interval, unchanged upstream", both, before=lambda: age_meta(db_path, 25))

    def change_first():
        age_meta(db_path, 25)
        lists.serve("/first.txt", "changed.txt", '"first-2"', "Sun, 08 Nov 2026 10:00:00 GMT")

    step("after the interval, changed upstream", both, before=change_first)
    step("a primary that fails, from its backup", [("/missing.txt", ["/backup.txt"]), ("/second.txt", [])])
    step("every URL of a list fails", [("/missing.txt", [])])
    server.shutdown()

    with open(args.out, "w") as fp:
        json.dump({
            "about": "What ace3's saq.nrd code did with tools/ace3/dumps/fixtures/nrd, written by "
            "tools/ace3/dumps/nrd_reference.py. The list server was at http://127.0.0.1:8091.",
            "lookups": lookup_results,
            "lines": lines,
            "refresh": steps,
        }, fp, indent=2, sort_keys=True, ensure_ascii=False)
        fp.write("\n")


if __name__ == "__main__":
    main()
