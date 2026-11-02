"""Dump ace3's observable types to JSON (PLAN.md step 1.14).

Runs inside ace3's dev container on ace3's Python, and writes nothing under /opt/ace:

    docker exec -i -e PYTHONDONTWRITEBYTECODE=1 -w /tmp ace-dev-1 \
        python3 - < tools/ace3/dumps/observable_types.py \
        > crates/ace-results/fixtures/ace3_observable_types.json

A type is listed when ace3 knows it either way it can: a Python class registered by importing
saq.observables, or an entry in etc/observable_types.yaml, which holds each type's parent
(`extends`), description, deprecated flag and default display type. That union is what
saq.observables.type_hierarchy.get_all_valid_types() returns. Integrations aren't loaded, so
only ace3's own types appear.
"""

import json
import subprocess
import sys

ACE3 = "/opt/ace"
sys.path.insert(0, ACE3)

from saq.observables.generator import OBSERVABLE_TYPE_MAPPING  # noqa: E402
import saq.observables  # noqa: E402,F401  registers every built-in type
from saq.observables.type_hierarchy import TypeHierarchy  # noqa: E402

hierarchy = TypeHierarchy()
hierarchy.load_yaml_config(f"{ACE3}/etc/observable_types.yaml")
yaml_types = hierarchy.yaml_declared_types()
if not yaml_types:
    sys.exit("etc/observable_types.yaml declared no types; refusing to write an empty fixture")

names = sorted(set(OBSERVABLE_TYPE_MAPPING) | hierarchy.all_known_types())

types = []
for name in names:
    cls = OBSERVABLE_TYPE_MAPPING.get(name)
    types.append(
        {
            "name": name,
            "extends": hierarchy.parent_of(name),
            "description": hierarchy.description_for(name),
            "deprecated": hierarchy.is_deprecated(name),
            "default_display_type": hierarchy.default_display_type_for(name),
            "python_class": f"{cls.__module__}.{cls.__qualname__}" if cls else None,
            "in_yaml": name in yaml_types,
        }
    )

commit = subprocess.run(
    ["git", "-C", ACE3, "rev-parse", "--short=8", "HEAD"],
    capture_output=True,
    text=True,
    check=False,
).stdout.strip()

json.dump(
    {
        "about": "ace3's observable types, written by tools/ace3/dumps/observable_types.py",
        "ace3_commit": commit or None,
        "types": types,
    },
    sys.stdout,
    indent=2,
    ensure_ascii=False,
)
sys.stdout.write("\n")
