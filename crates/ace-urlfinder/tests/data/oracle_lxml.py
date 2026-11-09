import json, os, sys, warnings
warnings.filterwarnings("ignore")
from io import BytesIO
from lxml import etree
from bs4 import BeautifulSoup
root = sys.argv[1]
out = {}
p = etree.HTMLParser(encoding="utf-8", default_doctype=False)
for name in sorted(os.listdir(root)):
    blob = open(os.path.join(root, name), "rb").read()
    text = blob.decode("utf-8", errors="ignore")
    try:
        t = etree.parse(BytesIO(text.encode("utf-8")), parser=p)
        if t.getroot() is None:
            r = {"output": {"html": "", "text": ""}}
        else:
            r = {"output": {"html": etree.tostring(t, encoding="unicode", method="html"), "text": etree.tostring(t, encoding="utf-8", method="text").decode("utf-8", "replace")}}
    except Exception as e:
        r = {"error": {"type": "lxml", "message": str(e)}}
    out[name + "|lxml"] = r
    try:
        out[name + "|soup"] = {"output": BeautifulSoup(text, "lxml").get_text()}
    except Exception as e:
        out[name + "|soup"] = {"output": None}
json.dump(out, sys.stdout, sort_keys=True)
