# Batch 8's email-tree modules: crafted bodies

PLAN.md 7.5 batch 8. A contained parser task is one thread with no exec, so each module is bounded for hostile input, and what crafted input costs it is measured against its limits. Each module has ace3's default limits, 300 s, 1 GiB and 300 CPU seconds.

Of the four, only `lure_url_analyzer` parses what an attacker wrote: the email's HTML bodies, on `ace-lxml`'s BeautifulSoup tree. The others read the tree the core sends, which the core caps at 20,000 observables and 20,000 results (`ace_sdk::tree`); each walk over it looks at each observable and result once, with a stack of its own, so a deep tree can't exhaust the task's.

The lure module's bounds:

- a body larger than 5 MiB isn't parsed, as in ace3, and the core doesn't send it (`Module::READS_TREE_FILES`);
- each body is parsed once, and each link's text and image are read from the nodes below it, whose span is worked out once for the whole body, so a link around the whole document costs one pass;
- the candidates are the URL observables below the email, which the URL module adds at most 12 of per file, scored once each.

Measured on 2026-11-10 on the dev container of `build-loop.md` (Rancher Desktop, 10 CPUs, 24 GB), with ace3's and budge's stacks up and ace3's trees being made in its container. In the dev container:

    cargo test -p ace-pool --features test-pools --test supervisor measure_lure -- --ignored --nocapture

submits each email to the real supervisor with the file type, email, URL, protected URL and lure modules, which run as `ace4-task` under Landlock and seccomp with their limits. 3 runs each, each in a new root. "Root" runs from the root's start to its last task's end, so it includes the email module, the URL module's search of each body and every upload and lease. The lure module runs last, so "Lure" is from the root's last other result landing to the lure's own: its hold, its lease, its bodies' download and its run. A dev build, unoptimized.

| Email | Size | End | Candidates | Root, seconds | Lure, seconds |
|---|---|---|---|---|---|
| `anchors_5mb`: a body of 5 MiB of links, about 140,000 | 5,242,798 | done | 5 | 6.2 to 6.3 | 0.59 to 0.61 |
| `one_anchor_deep_5mb`: one link around 870,000 unclosed `<div>`s | 5,242,973 | done | 1 | 2.6 to 2.8 | 1.30 to 1.35 |
| `anchor_text_5mb`: one link around 5 MiB of words | 5,242,977 | done | 1 | 1.8 to 2.0 | 0.59 to 0.60 |
| `form_of_links_5mb`: a form around 140,000 links | 5,242,975 | done | 2 | 2.7 to 2.9 | 0.81 to 0.86 |
| `over_5mb`: a body of 6 MiB, which isn't parsed | 6,291,589 | done | 1 | 2.4 to 2.6 | 0.51 to 0.53 |
| `bodies_20x1mb`: 20 bodies of 1 MiB of links | 20,971,943 | done | 5 | 14.2 to 14.7 | 1.57 to 1.58 |

Every task ended `done`, far inside its deadline.
