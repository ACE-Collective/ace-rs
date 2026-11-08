#!/usr/bin/env bash
# Writes the two tables ace-mod-brocess's look-alike checks read (crates/ace-mod-brocess/src/similarity.rs)
# from the data confusable-homoglyphs 3.3.1 ships in ace3's image, which ace3's saq/domain_similarity.py
# reads (PLAN.md 7.4). It reads ace3's installed package in ace3's dev container and writes nothing there.
#
#   scripts.tsv  each range of code points and its script alias, as categories.json has them
#   folds.tsv    each character that isn't LATIN and looks like one that is, and the first of its
#                homoglyphs: what is_confusable(value, greedy=True, preferred_aliases=["latin"])
#                maps it to in _unicode_fold
#
#     tools/ace3/dumps/confusables.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out="$here/../../../crates/ace-mod-brocess/src/data"
script='
import sys
from confusable_homoglyphs import categories, confusables
which = sys.argv[1]
if which == "scripts":
    data = categories.categories_data
    aliases = data["iso_15924_aliases"]
    print("# start\tend\talias: confusable-homoglyphs 3.3.1 categories.json, by tools/ace3/dumps/confusables.sh")
    for start, end, alias, _category in data["code_points_ranges"]:
        print(f"{start:x}\t{end:x}\t{aliases[alias]}")
else:
    print("# character\tfold, as code points: confusable-homoglyphs 3.3.1 confusables.json, by tools/ace3/dumps/confusables.sh")
    # _unicode_fold looks up each character of a value, so only single characters can match
    for char in sorted(c for c in confusables.confusables_data if len(c) == 1):
        found = confusables.is_confusable(char, greedy=True, preferred_aliases=["latin"])
        if not found:
            continue
        homoglyphs = found[0]["homoglyphs"]
        if homoglyphs:
            fold = " ".join(f"{ord(c):x}" for c in homoglyphs[0]["c"])
            print(f"{ord(char):x}\t{fold}")
'
docker exec -i -e PYTHONDONTWRITEBYTECODE=1 ace-dev-1 /venv/bin/python3 -I -c "$script" scripts > "$out/scripts.tsv"
docker exec -i -e PYTHONDONTWRITEBYTECODE=1 ace-dev-1 /venv/bin/python3 -I -c "$script" folds > "$out/folds.tsv"
