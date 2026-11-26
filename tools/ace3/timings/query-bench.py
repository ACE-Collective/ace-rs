"""Times ace3's own per-observable queries against ace3's dev databases, read only (PLAN.md 3.6):
the SELECT user_defined_tagging sends (saq/modules/tag.py) and the two brocess sums the conversation
frequency module sends (saq/brocess.py), each through ace3's get_db_connection as the modules call
it. make-trees answers both from memory, since writing their rows into ace3's databases isn't
allowed, so this is what the timings leave out (docs/measurements/module-timings.md). It writes
nothing, and prints JSON: the tables' sizes, then per run each query's median, p10, p90 and mean.

    docker exec -i -e PYTHONPATH=/opt/ace -e SAQ_SKIP_LOCAL_SAQ_YAML=1 -w /opt/ace ace-dev-1 \
        /venv/bin/python3 - CALLS RUNS < tools/ace3/timings/query-bench.py

ace3's local overlay is skipped as make-dumps skips it: it holds live credentials and doesn't load
in a fresh process."""

import hashlib
import json
import os
import random
import statistics
import sys
import tempfile
import time

CALLS = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
RUNS = int(sys.argv[2]) if len(sys.argv) > 2 else 3

work = tempfile.mkdtemp(prefix="ace-rs-bench-")
for sub in ("data", "tmp", "home"):
    os.makedirs(os.path.join(work, sub))
with open(os.path.join(work, "logging.yaml"), "w") as fp:
    fp.write("version: 1\nroot:\n  level: WARNING\n  handlers: []\n")
os.environ["HOME"] = os.path.join(work, "home")
os.chdir(work)

from saq.environment import initialize_environment  # noqa: E402

initialize_environment(
    saq_home="/opt/ace",
    data_dir=os.path.join(work, "data"),
    temp_dir=os.path.join(work, "tmp"),
    config_paths=[],
    logging_config_path=os.path.join(work, "logging.yaml"),
)

from saq.brocess import query_brocess_by_email_conversation, query_brocess_by_source_email  # noqa: E402
from saq.database.pool import get_db_connection  # noqa: E402

TAG_SQL = """
SELECT
    `tags`.`name`
FROM
    observables
JOIN
    observable_tag_mapping ON observables.id = observable_tag_mapping.observable_id
    JOIN tags ON observable_tag_mapping.tag_id = tags.id
WHERE
    `observables`.`type` = %s AND `observables`.`sha256` = UNHEX(%s)
"""


def scalar(sql, name="ace"):
    with get_db_connection(name) as db:
        cursor = db.cursor()
        cursor.execute(sql)
        return cursor.fetchall()


sizes = {
    "observables": scalar("SELECT COUNT(*) FROM observables")[0][0],
    "observable_tag_mapping": scalar("SELECT COUNT(*) FROM observable_tag_mapping")[0][0],
    "tags": scalar("SELECT COUNT(*) FROM tags")[0][0],
}
try:
    sizes["smtplog"] = scalar("SELECT COUNT(*) FROM smtplog", "brocess")[0][0]
except Exception as e:  # brocess may not be set up in the dev stack
    sizes["smtplog"] = f"unavailable: {e}"

# half observables that exist (with a tag where there are any), half that don't
tagged = scalar(
    "SELECT o.type, HEX(o.sha256) FROM observables o JOIN observable_tag_mapping m ON m.observable_id = o.id LIMIT 500"
)
existing = scalar("SELECT type, HEX(sha256) FROM observables ORDER BY id DESC LIMIT 1000")
present = list(tagged) + list(existing)
rng = random.Random(1)
absent = [
    (rng.choice(["fqdn", "ipv4", "url", "file", "email_address"]), hashlib.sha256(str(i).encode()).hexdigest())
    for i in range(1000)
]


def tag_query(kind, sha256):
    with get_db_connection() as db:
        cursor = db.cursor()
        cursor.execute(TAG_SQL, (kind, sha256))
        return [row for row in cursor]


senders = []
if isinstance(sizes["smtplog"], int) and sizes["smtplog"]:
    senders = scalar("SELECT source, destination FROM smtplog LIMIT 500", "brocess")
fake_senders = [(f"bench{i}@example.com", f"rcpt{i}@example.org") for i in range(500)]


def timed(call, args_list):
    times = []
    for args in args_list:
        start = time.perf_counter()
        call(*args)
        times.append(time.perf_counter() - start)
    return times


def summary(times):
    times = sorted(times)
    return {
        "calls": len(times),
        "median_ms": statistics.median(times) * 1000,
        "p10_ms": times[len(times) // 10] * 1000,
        "p90_ms": times[len(times) * 9 // 10] * 1000,
        "mean_ms": statistics.mean(times) * 1000,
    }


# one call first, so the pool's connection is made outside the timings, as in a long-running worker
tag_query(*absent[0])
results = {"sizes": sizes, "tag_present_sample": len(present), "runs": []}
for run in range(RUNS):
    mix = [present[i % len(present)] if (i % 2 and present) else absent[i % len(absent)] for i in range(CALLS)]
    entry = {"user_defined_tagging": summary(timed(tag_query, mix))}
    if not isinstance(sizes["smtplog"], str):
        pool = list(senders) + fake_senders
        pairs = [pool[i % len(pool)] for i in range(CALLS)]
        entry["brocess_source"] = summary(timed(query_brocess_by_source_email, [(s,) for s, _ in pairs]))
        entry["brocess_conversation"] = summary(timed(query_brocess_by_email_conversation, pairs))
    results["runs"].append(entry)
print(json.dumps(results, indent=1))
