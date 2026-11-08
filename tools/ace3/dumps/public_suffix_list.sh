#!/usr/bin/env bash
# Copies the public suffix list that ace3's tldextract ships into ace-sdk (ace_sdk::domains), which reduces
# a domain to its registrable domain with it as ace3 does (PLAN.md 1.27, 7.4). It reads ace3's
# installed package in ace3's dev container and writes nothing there.
#
#     tools/ace3/dumps/public_suffix_list.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
docker exec ace-dev-1 cat /venv/lib/python3.14/site-packages/tldextract/.tld_set_snapshot \
    > "$here/../../../crates/ace-sdk/src/public_suffix_list.dat"
