"""Load every hunt in a set of rule directories with ace3's own loader and write what each one
loads as, or the error it fails with (PLAN.md step 6.2).

It runs inside ace3's dev container on ace3's Python, writing only under its work directory in
/tmp, and reads the hunts where they are:

    docker exec -i -e PYTHONDONTWRITEBYTECODE=1 -e SAQ_SKIP_LOCAL_SAQ_YAML=1 ace-dev-1 \\
        /venv/bin/python3 - --work /tmp/ace4-dumps/hunts --root /opt/ace/signatures \\
        --rule-dir splunk=hunts/splunk --rule-dir logscale=hunts/logscale \\
        --rule-dir rapid7=hunts/rapid7 < tools/ace3/hunts/load_hunts.py

tools/ace3/hunts/make-hunts calls it. For each hunt type it does what HuntManager's
load_hunts_from_config does (saq/collectors/hunter/manager.py), with the parts that reach
outside the hunt files left out:

- _list_hunt_yaml lists the hunts, through ace3's own method;
- each hunt loads as its class's load_hunt_config does, load_from_yaml with the type's config
  class (SplunkHuntConfig, LogscaleHuntConfig, Rapid7HuntConfig), and then as QueryHunt.load_hunt
  does, reading its query file when it names one;
- SplunkHunt's constructor looks its splunk_config up in ace3's configuration, so that lookup is
  made too;
- add_hunt's checks follow: the hunt's type must be the manager's, and its name must not repeat
  a name loaded before it in the same type, in listing order.

What's left out is the rest of each class's constructor, which needs credentials or an API:
LogscaleHunt's get_endpoint_auth and Rapid7Hunt's log name lookup (6.4 brings those).

The output, hunts.json in the work directory, lists every hunt file by its path under --root,
with its type and either `loaded`, the config as pydantic dumps it with its aliases plus the
predefined commands, the files it read and its query file's text, or `error`, the exception's
class and its text or, for a ValidationError, the model's name and each error's type, location
and message. Paths under --root are written as `$ROOT/...`, and the work directory as `$WORK`.
Entries are in the order ace3 lists them, which is os.scandir's.
"""

import argparse
import json
import os
import sys

ACE3 = "/opt/ace"

# the hunt types make-hunts loads, and the config class each one's hunt class validates with
CONFIG_CLASSES = {
    "splunk": ("saq.collectors.hunter.splunk_hunter", "SplunkHuntConfig"),
    "logscale": ("endpoint.collectors.hunter.logscale_hunter", "LogscaleHuntConfig"),
    "rapid7": ("rapid7.collectors.hunter.rapid7_hunter", "Rapid7HuntConfig"),
}

# SplunkHunt's constructor looks up the splunk config its hunt names, `default` unless it says
# otherwise, and ace3's shipped configuration has none of that name without the local overlay. This
# one is loaded for the run, as `ace -c` would; nothing connects to it.
SPLUNK_CONFIG = """\
splunk_config_default:
  name: default
  enabled: true
  host: 127.0.0.1
  port: 8089
  username: ace4
  password: ace4-unused
  timezone: GMT
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


def parse_args():
    parser = argparse.ArgumentParser(prog="load_hunts.py")
    parser.add_argument("--work", required=True, help="work directory under /tmp; replaced if it exists")
    parser.add_argument("--root", required=True, help="the directory hunt paths are written relative to")
    parser.add_argument("--rule-dir", action="append", default=[], metavar="TYPE=DIR",
                        help="a hunt type and one of its rule directories, relative to --root")
    args = parser.parse_args(sys.argv[1:])
    if not args.work.startswith("/tmp/"):
        parser.error("--work must be under /tmp")
    return args


def relative(value, root, work):
    if isinstance(value, dict):
        return {relative(k, root, work): relative(v, root, work) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [relative(v, root, work) for v in value]
    if isinstance(value, str):
        return value.replace(root, "$ROOT").replace(work, "$WORK")
    return value


def describe_error(e):
    from pydantic import ValidationError

    if not isinstance(e, ValidationError):
        return {"class": type(e).__name__, "message": str(e)}
    # str() of a ValidationError repeats the errors with their inputs and a link per error
    errors = [
        {"type": error["type"], "loc": list(error["loc"]), "msg": error["msg"]}
        for error in e.errors(include_url=False, include_input=False, include_context=False)
    ]
    return {"class": type(e).__name__, "title": e.title, "errors": errors}


def load_one(path, hunt_type, config_class, names):
    from saq.collectors.hunter.loader import load_from_yaml
    from saq.configuration.config import get_config
    from saq.query.config import load_query_from_file

    config, files = load_from_yaml(path, config_class)
    loaded_query = None
    if config.query_file_path:
        loaded_query = load_query_from_file(config.query_file_path)
    if hunt_type == "splunk":
        get_config().get_splunk_config(config.splunk_config)

    # HuntManager.add_hunt
    if config.type_ != hunt_type:
        raise ValueError(f"hunt Hunt({config.name}[{config.type_}]) has wrong type for {hunt_type}")
    if config.name in names:
        raise KeyError(f"duplicate hunt {config.name}")
    names.add(config.name)

    return {
        "config": config.model_dump(mode="json", by_alias=True),
        "commands": [c.model_dump(mode="json", by_alias=True) for c in config._predefined_commands],
        "files": sorted(files),
        "query": loaded_query,
    }


def main():
    args = parse_args()
    work = os.path.abspath(args.work)
    root = os.path.abspath(args.root)
    if os.path.exists(work):
        import shutil

        shutil.rmtree(work)
    for sub in ("data", "tmp", "home"):
        os.makedirs(os.path.join(work, sub))
    with open(os.path.join(work, "logging.yaml"), "w") as fp:
        fp.write(LOGGING_CONFIG)
    with open(os.path.join(work, "saq.splunk.yaml"), "w") as fp:
        fp.write(SPLUNK_CONFIG)
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

    import importlib

    from saq.collectors.hunter.manager import HuntManager

    rule_dirs = {}
    for spec in args.rule_dir:
        hunt_type, _, directory = spec.partition("=")
        rule_dirs.setdefault(hunt_type, []).append({"rule_dir": os.path.join(root, directory)})

    hunts = []
    for hunt_type, dirs in rule_dirs.items():
        module_name, class_name = CONFIG_CLASSES[hunt_type]
        config_class = getattr(importlib.import_module(module_name), class_name)
        # only _list_hunt_yaml is used, which reads rule_dirs and nothing set up by __init__
        manager = HuntManager.__new__(HuntManager)
        manager.rule_dirs = dirs
        names = set()
        for path in manager._list_hunt_yaml():
            entry = {"path": os.path.relpath(path, root), "type": hunt_type}
            try:
                entry["loaded"] = load_one(path, hunt_type, config_class, names)
            except Exception as e:
                entry["error"] = describe_error(e)
            hunts.append(relative(entry, root, work))

    import subprocess

    def commit(directory):
        return subprocess.run(["git", "-C", directory, "rev-parse", "HEAD"], capture_output=True,
                              text=True).stdout.strip() or None

    output = {"ace3_commit": commit(ACE3), "root_commit": commit(root), "hunts": hunts}
    with open(os.path.join(work, "hunts.json"), "w") as fp:
        json.dump(output, fp, indent=1, sort_keys=True, ensure_ascii=False)
        fp.write("\n")


if __name__ == "__main__":
    main()
