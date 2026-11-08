"""Render hunt templates with ace3's own Jinja code and write what each gives (PLAN.md step 6.3).

It runs inside ace3's dev container on ace3's Python, from a directory make-templates copies it
to beside load_hunts.py, writing only under its work directory in /tmp:

    render_templates.py --work DIR cases CASES.yaml
    render_templates.py --work DIR signatures --root /opt/ace/signatures --rule-dir TYPE=DIR ...

Every render is a call of ace3's own functions (saq/query/summary_detail_rendering.py,
template_rendering.py and extraction.py, and QueryHunt._render_name), named as the entry's `call`:

    jinja, jinja_strict        render_jinja_template(template, event, strict)
    event, event_strict        render_event_template(template, event, strict=...)
    multi, multi_strict        render_event_template_multi(template, event, strict=...)
    rows, rows_strict          render_event_templates_multi(templates, event, strict=...)
    grouped, grouped_strict    render_jinja_template(template, {"events": events}, strict)
    shared                     render_event_template of the first template, then
                               render_jinja_template of the second, against one event
    name                       QueryHunt._render_name
    interpolate                extraction._interpolate_strict
    sd_content, sd_header      extraction.render_sd_content and render_sd_header
    sd_grouped                 a grouped jinja summary detail: render_jinja_template with
                               {"events": events}, skipped on UndefinedError, None or blank

A result is the text, null for ace3's None, {"undefined": true} for an UndefinedError that
escaped, or the list a multi render gives.

`cases` renders tools/ace3/hunts/templates/cases.yaml: each case has templates, events and the
calls to make, and every template is rendered by every call against every event (a `rows` call
takes the case's templates together). `signatures` loads every hunt with ace3's loader, as
load_hunts.py does, and renders each of its templates with the call ace3's hunter makes for it
(saq/collectors/hunter/query_hunter.py and saq/query/extraction.py) against a fixed set of events
built from the fields the hunt reads (see `variants`). Each entry carries its inputs, so ace4
renders the same, and the output holds the hunts' own text: it's git-ignored.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

UNDEFINED = {"undefined": True}


def parse_args():
    parser = argparse.ArgumentParser(prog="render_templates.py")
    parser.add_argument("--work", required=True)
    sub = parser.add_subparsers(dest="set", required=True)
    cases = sub.add_parser("cases")
    cases.add_argument("file")
    sigs = sub.add_parser("signatures")
    sigs.add_argument("--root", required=True)
    sigs.add_argument("--rule-dir", action="append", default=[], metavar="TYPE=DIR")
    args = parser.parse_args(sys.argv[1:])
    if not args.work.startswith("/tmp/"):
        parser.error("--work must be under /tmp")
    return args


def render(call, templates, event, events=None, sd=None, name_uuid="u"):
    """One render by ace3's code."""
    from jinja2 import UndefinedError

    from saq.collectors.hunter.query_hunter import QueryHunt
    from saq.query.config import SummaryDetailConfig
    from saq.query.extraction import _interpolate_strict, render_sd_content, render_sd_header
    from saq.query.summary_detail_rendering import render_jinja_template
    from saq.query.template_rendering import (
        render_event_template,
        render_event_template_multi,
        render_event_templates_multi,
    )

    strict = call.endswith("_strict")
    base = call.removesuffix("_strict")
    try:
        if base == "jinja":
            return render_jinja_template(templates[0], event, strict=strict)
        if base == "event":
            return render_event_template(templates[0], event, strict=strict)
        if base == "multi":
            return render_event_template_multi(templates[0], event, strict=strict)
        if base == "rows":
            return render_event_templates_multi(list(templates), event, strict=strict)
        if base == "grouped":
            return render_jinja_template(templates[0], {"events": events}, strict=strict)
        if base == "name":

            class Hunt:
                pass

            hunt = Hunt()
            hunt.name = templates[0]
            hunt.uuid = name_uuid
            return QueryHunt._render_name(hunt, event)
        if base == "interpolate":
            return _interpolate_strict(templates[0], event)
        config = SummaryDetailConfig(**sd)
        if base == "sd_content":
            return render_sd_content(config, event)
        if base == "sd_header":
            ok, header = render_sd_header(config, event)
            return {"ok": ok, "header": header}
        if base == "sd_grouped":
            try:
                content = render_jinja_template(
                    config.content, {"events": events}, strict=config.required_fields is None
                )
            except UndefinedError:
                return None
            if content is None or not content.strip():
                return None
            return content
    except UndefinedError:
        return UNDEFINED
    raise SystemExit(f"no call {call}")


def jsonable(value):
    if isinstance(value, tuple):
        return [jsonable(v) for v in value]
    if isinstance(value, list):
        return [jsonable(v) for v in value]
    return value


def run_cases(path):
    import copy

    import yaml

    with open(path) as fp:
        cases = yaml.safe_load(fp)
    out = []
    for case in cases:
        renders = {}
        events = case.get("events", [{}])
        templates = case["templates"]
        for call in case["calls"]:
            if call == "shared":
                # the hunter renders each of a hunt's templates against the same event: the first
                # template with render_event_template, the second with render_jinja_template
                for e, event in enumerate(events):
                    shared = copy.deepcopy(event)
                    first = render("event", templates[:1], shared)
                    second = render("jinja", templates[1:2], shared)
                    renders[f"all {call} {e}"] = jsonable([first, second])
                continue
            if call.startswith("rows"):
                for e, event in enumerate(events):
                    renders[f"all {call} {e}"] = jsonable(render(call, templates, copy.deepcopy(event)))
                continue
            if call.startswith("grouped"):
                for t, template in enumerate(templates):
                    renders[f"{t} {call}"] = jsonable(render(call, [template], None, events=copy.deepcopy(events)))
                continue
            for t, template in enumerate(templates):
                sd = None
                if call.startswith("sd_"):
                    sd = {"content": template, "header": template, "format": "md", **case.get("sd", {})}
                if call == "sd_grouped":
                    renders[f"{t} {call}"] = jsonable(
                        render(call, [template], None, events=copy.deepcopy(events), sd=sd))
                    continue
                for e, event in enumerate(events):
                    # each render gets its own copy, so one that changes the event doesn't reach
                    # the next; the `shared` call shows what happens when they share one
                    renders[f"{t} {call} {e}"] = jsonable(render(call, [template], copy.deepcopy(event), sd=sd))
        out.append({"path": case["name"], "templates": templates, "events": events, "renders": renders})
    return out


# The events a hunt's templates render against in the signatures comparison. Each is built from the
# fields the hunt reads: the names, attribute chains and constant keys in its templates, written as
# the flat dotted keys Splunk and LogScale return, and the fields its mappings and summary details
# name. A value is chosen by the field's name so a template's own tests (an address, a user, a
# count) see something like what a real event carries.
SAMPLES = [
    (("ip", "addr", "src", "dst", "dest", "client", "remote"), ["10.20.30.40", "192.0.2.7"]),
    (("user", "upn", "account", "email", "sender", "recipient", "mail", "from", "to"),
     ["alice@example.com", "Bob.Smith@example.org"]),
    (("host", "computer", "device", "machine", "aid"), ["WS-0142", "srv-db-02.corp.example.com"]),
    (("domain", "fqdn", "dns", "query"), ["example.com", "login.evil.example.net"]),
    (("url", "uri", "link", "referrer"), ["https://example.com/a/b?q=1&r=<x>", "http://192.0.2.7:8080/"]),
    (("time", "timestamp", "date", "epoch", "created", "_time"), ["2026-11-08T12:34:56Z", "1762605296"]),
    (("count", "total", "num", "score", "port", "size", "bytes", "len"), ["42", "0"]),
    (("hash", "sha256", "md5", "sha1"), ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                         "D41D8CD98F00B204E9800998ECF8427E"]),
    (("cmd", "command", "process", "image", "parent"), ['powershell.exe -enc "SQBFAFgA"', "cmd.exe /c whoami"]),
    (("file", "path", "name"), ["C:\\Users\\alice\\Downloads\\Invoice 2026.pdf.exe", "report.docx"]),
    (("status", "result", "action", "outcome", "verdict", "type"), ["Success", "failure"]),
]


def sample(field, n):
    lower = field.lower()
    for keys, values in SAMPLES:
        if any(k in lower for k in keys):
            return values[n % len(values)]
    return f"{field} value {n + 1}"


GLOBAL_NAMES = {"range", "dict", "namespace", "loop", "caller", "varargs", "kwargs", "true", "false",
                "none", "True", "False", "None", "events", "cycler", "joiner", "lipsum"}
METHODS = {"get", "items", "keys", "values", "split", "lower", "upper", "strip", "startswith", "endswith",
           "replace", "join", "append", "update", "setdefault"}


def template_fields(template, consts=None):
    """The fields a template reads, in the order they appear: each name, attribute chain and
    constant key, less the names it sets itself and Jinja's own. With `consts`, also the
    constants each field is compared with (`==`, `in`, `startswith` and the like), by field and by
    its last part, which the `match` events use."""
    from jinja2 import Environment, nodes

    try:
        tree = Environment().parse(template)
    except Exception:
        return []
    stored = {n.name for n in tree.find_all(nodes.Name) if n.ctx in ("store", "param")}
    stored |= GLOBAL_NAMES
    fields = []

    def add(f):
        if f and f not in fields:
            fields.append(f)

    def chain(node):
        parts = []
        while True:
            if isinstance(node, nodes.Name):
                parts.append(node.name)
                return list(reversed(parts))
            if isinstance(node, nodes.Getattr):
                parts.append(node.attr)
                node = node.node
            elif isinstance(node, nodes.Getitem) and isinstance(node.arg, nodes.Const) and isinstance(
                    node.arg.value, str):
                parts.append(node.arg.value)
                node = node.node
            else:
                return None

    aliases = {}

    def field_of(node):
        """The field an operand reads: a chain, `x.get('k')` or `x['k']`, under any filters and
        string methods, or a name set from one."""
        while True:
            if isinstance(node, nodes.Filter) and node.node is not None:
                node = node.node
            elif isinstance(node, nodes.Call) and isinstance(node.node, nodes.Getattr) and \
                    node.node.attr in ("lower", "upper", "strip", "lstrip", "rstrip", "casefold", "title"):
                node = node.node.node
            else:
                break
        if isinstance(node, nodes.Name) and node.name in aliases:
            return aliases[node.name]
        if isinstance(node, nodes.Call) and isinstance(node.node, nodes.Getattr) and node.node.attr == "get" \
                and node.args and isinstance(node.args[0], nodes.Const) and isinstance(node.args[0].value, str):
            return node.args[0].value
        c = chain(node)
        if c and c[0] not in stored:
            return ".".join(c)
        if c and len(c) > 1:
            return c[-1]
        return None

    def note(field, value):
        if consts is None or field is None or isinstance(value, bool) or value is None:
            return
        values = [value]
        if isinstance(value, (int, float)):
            values = [str(value), str(value + 1), value, value + 1]
        for key in (field, field.split(".")[-1]):
            bucket = consts.setdefault(key, [])
            for v in values:
                if v not in bucket and len(bucket) < 8:
                    bucket.append(v)

    def const_values(node):
        if isinstance(node, nodes.Const):
            return [node.value]
        if isinstance(node, (nodes.List, nodes.Tuple)):
            return [i.value for i in node.items if isinstance(i, nodes.Const)]
        return []

    for node in tree.find_all(nodes.Assign):
        if isinstance(node.target, nodes.Name):
            f = field_of(node.node)
            if f:
                aliases[node.target.name] = f

    for node in tree.find_all((nodes.Name, nodes.Getattr, nodes.Getitem, nodes.Call, nodes.Compare)):
        if isinstance(node, nodes.Compare):
            left = node.expr
            for op in node.ops:
                for a, b in ((left, op.expr), (op.expr, left)):
                    for v in const_values(b):
                        note(field_of(a), v)
                left = op.expr
            continue
        if isinstance(node, nodes.Call):
            if isinstance(node.node, nodes.Getattr) and node.node.attr in ("startswith", "endswith") and node.args:
                for v in const_values(node.args[0]):
                    note(field_of(node.node.node), v)
            # row.get("field") and d["field"] name fields of whatever the template reads them from
            if isinstance(node.node, nodes.Getattr) and node.node.attr == "get" and node.args and \
                    isinstance(node.args[0], nodes.Const) and isinstance(node.args[0].value, str):
                add(node.args[0].value)
            continue
        if isinstance(node, nodes.Getitem) and isinstance(node.arg, nodes.Const) and isinstance(
                node.arg.value, str):
            add(node.arg.value)
        c = chain(node)
        if c and c[0] not in stored and c[-1] not in METHODS:
            add(".".join(c))
    return fields


def mixed(depth):
    value = {"text": "x", "number": 1, "float": 1.5, "true": True, "false": False, "null": None,
             "list": [1, "a", None], "empty_list": [], "empty_object": {}}
    if depth > 0:
        value["object"] = mixed(depth - 1)
        value["objects"] = [mixed(depth - 1)] if depth > 4 else []
    return value


def variants(fields, consts):
    """The fixed events for a hunt whose templates read `fields`: what each covers.

    strings  every field a realistic string
    second   every field the other realistic string, for a second event in a group
    lists    every field a two-item list, as a Splunk multivalue field is
    numbers  every field an integer, as LogScale and Rapid7 give numbers
    json     every field a JSON string of an object holding every field, for fromjson
    nested   every field an object holding every field, for .get() and attributes on a value
    records  every field a list of two objects holding every field, the first with the constants
             the templates compare a field with where there are any, as a correlation's rows are
    mixed    every field an object holding a value of each JSON type, nested six deep, for
             templates that walk a value and branch on its type
    nulls    every field null
    blank    every field an empty string
    empty    no fields at all
    match1.. every field one of the constants the templates compare it with (the first, the
             second, and so on, wrapping round), so a branch on `== 'Success'`, `in [...]` or
             `startswith('10.')` is taken; a field compared with nothing keeps its string, and
             the objects of `json` and `nested` are built the same way
    """
    leaf = sorted({f.split(".")[-1] for f in fields} | set(consts))

    def obj(n):
        return {k: sample(k, n) for k in leaf}

    def pick(name, k, n):
        values = consts.get(name) or consts.get(name.split(".")[-1])
        return values[k % len(values)] if values else sample(name, n)

    out = {
        "strings": {f: sample(f, 0) for f in fields},
        "second": {f: sample(f, 1) for f in fields},
        "lists": {f: [sample(f, 0), sample(f, 1)] for f in fields},
        "numbers": {f: i + 1 for i, f in enumerate(fields)},
        "json": {f: json.dumps(obj(0)) for f in fields},
        "nested": {f: obj(0) for f in fields},
        "records": {f: [{k: pick(k, 0, 0) for k in leaf}, obj(1)] for f in fields},
        "mixed": {f: mixed(6) for f in fields},
        "nulls": {f: None for f in fields},
        "blank": {f: "" for f in fields},
        "empty": {},
    }
    width = max((len(v) for v in consts.values()), default=0)

    for k in range(width):
        inner = {key: pick(key, k, 0) for key in leaf}
        event = {f: pick(f, k, 0) for f in fields}
        # a field read as an object (`x.get('k')`, `x.k`) whose own value isn't compared gets one
        for f in fields:
            if not (consts.get(f) or consts.get(f.split(".")[-1])) and any(
                    other.startswith(f + ".") for other in fields):
                event[f] = dict(inner)
        out[f"match{k + 1}"] = event
    return out


def hunt_templates(config):
    """Each template of a hunt with the call ace3's hunter renders it with, in the order of
    ace4's HuntConfig::templates()."""
    out = []

    def add(at, call, templates, sd=None):
        out.append({"at": at, "call": call, "templates": templates, "sd": sd})

    add("name", "name", [config.name])
    if config.playbook_url:
        add("playbook_url", "event_strict", [config.playbook_url])
    if config.dedup_key:
        add("dedup_key", "event_strict", [config.dedup_key])
    for i, tag in enumerate(config.tags):
        add(f"tags/{i}", "multi_strict", [tag])
    for i, link in enumerate(config.pivot_links):
        if isinstance(link.get("url"), str) and isinstance(link.get("text"), str):
            add(f"pivot_links/{i}", "rows_strict", [link["url"], link["text"]])
    for i, sd in enumerate(config.summary_details):
        spec = {"content": sd.content, "header": sd.header, "format": sd.format,
                "required_fields": sd.required_fields}
        if sd.grouped and sd.format == "jinja":
            add(f"summary_details/{i}/content", "sd_grouped", [sd.content], spec)
        else:
            add(f"summary_details/{i}/content", "sd_content", [sd.content], spec)
        if sd.header is not None:
            add(f"summary_details/{i}/header", "sd_header", [sd.header], spec)
    for i, m in enumerate(config.observable_mapping):
        at = f"observable_mapping/{i}"
        if m.type_is_templated:
            add(f"{at}/type", "event_strict", [m.type])
        if m.value is not None:
            add(f"{at}/value", "interpolate", [m.value])
        if m.file_name is not None:
            add(f"{at}/file_name", "interpolate", [m.file_name])
        for j, tag in enumerate(m.tags):
            add(f"{at}/tags/{j}", "interpolate", [tag])
        for j, d in enumerate(m.directives):
            add(f"{at}/directives/{j}", "interpolate", [d])
        for j, r in enumerate(m.relationships):
            add(f"{at}/relationships/{j}/target/value", "interpolate", [r.target.value])
    return out


def run_signatures(args, work):
    import copy

    import load_hunts

    load_hunts.setup(work)
    import importlib

    from saq.collectors.hunter.loader import load_from_yaml
    from saq.collectors.hunter.manager import HuntManager

    root = os.path.abspath(args.root)
    out = []
    for spec in args.rule_dir:
        hunt_type, _, directory = spec.partition("=")
        module_name, class_name = load_hunts.CONFIG_CLASSES[hunt_type]
        config_class = getattr(importlib.import_module(module_name), class_name)
        manager = HuntManager.__new__(HuntManager)
        manager.rule_dirs = [{"rule_dir": os.path.join(root, directory)}]
        for path in manager._list_hunt_yaml():
            try:
                config, _ = load_from_yaml(path, config_class)
            except Exception:
                # 6.2's comparison covers hunts that don't load
                continue
            items = hunt_templates(config)
            fields = []
            consts = {}
            for item in items:
                for t in item["templates"]:
                    for f in template_fields(t, consts):
                        if f not in fields:
                            fields.append(f)
            for m in config.observable_mapping:
                for f in m.fields:
                    if f not in fields:
                        fields.append(f)
            for sd in config.summary_details:
                for f in (sd.required_fields or []) + (sd.dedup_fields or []):
                    if f not in fields:
                        fields.append(f)
            events = variants(fields, consts)
            renders = {}
            for item in items:
                for name, event in events.items():
                    # each render gets its own copy: ace3's _expand_dotted_keys writes into an
                    # event's nested dict when a flat key names a path in it, as these events'
                    # `a` and `a.b` can (the shared-event case shows that)
                    group = copy.deepcopy([event, events["second"]])
                    result = render(item["call"], item["templates"], copy.deepcopy(event), events=group,
                                    sd=item["sd"], name_uuid=config.uuid)
                    renders[f"{item['at']} {name}"] = jsonable(result)
            out.append({
                "path": os.path.relpath(path, root),
                "type": hunt_type,
                # a grouped summary detail renders [event, events["second"]]
                "events": events,
                "templates": {item["at"]: {"call": item["call"], "templates": item["templates"],
                                           "sd": item["sd"]} for item in items},
                "renders": renders,
            })
    return out


def main():
    args = parse_args()
    work = os.path.abspath(args.work)
    os.makedirs(work, exist_ok=True)
    if args.set == "cases":
        import load_hunts

        load_hunts.setup(os.path.join(work, "env"))
        hunts = run_cases(args.file)
        root_commit = None
    else:
        hunts = run_signatures(args, os.path.join(work, "env"))
        import subprocess

        root_commit = subprocess.run(["git", "-C", args.root, "rev-parse", "HEAD"], capture_output=True,
                                     text=True).stdout.strip() or None
    import subprocess

    ace3_commit = subprocess.run(["git", "-C", "/opt/ace", "rev-parse", "HEAD"], capture_output=True,
                                 text=True).stdout.strip() or None
    output = {"ace3_commit": ace3_commit, "root_commit": root_commit, "hunts": hunts}
    with open(os.path.join(work, "templates.json"), "w") as fp:
        # keys in the order each dict has them, since a template iterating one sees that order
        json.dump(output, fp, indent=1, ensure_ascii=False)
        fp.write("\n")


if __name__ == "__main__":
    main()
