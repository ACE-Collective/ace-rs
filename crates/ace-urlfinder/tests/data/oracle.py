"""Run urlfinderlib on every file of a directory, in each mode, printing JSON lines."""
import json, os, sys, warnings
warnings.filterwarnings("ignore")
from urlfinderlib import find_urls, find_urls_in_text
root = sys.argv[1]
out = {}
for name in sorted(os.listdir(root)):
    blob = open(os.path.join(root, name), "rb").read()
    for mode in ("default", "domain", "text", "textdomain", "plain", "base"):
        try:
            if mode == "default": r = find_urls(blob)
            elif mode == "domain": r = find_urls(blob, domain_as_url=True)
            elif mode == "text": r = find_urls_in_text(blob)
            elif mode == "textdomain": r = find_urls_in_text(blob, domain_as_url=True)
            elif mode == "plain": r = find_urls(blob, mimetype="text/plain")
            elif mode == "base": r = find_urls(blob, base_url="https://base.example.com/dir/page.html", mimetype="text/html")
            res = {"output": sorted(r)}
        except Exception as e:
            res = {"error": {"type": type(e).__name__, "message": str(e)[:200]}}
        out[f"{name}|{mode}"] = res
json.dump(out, sys.stdout, indent=0, sort_keys=True)
