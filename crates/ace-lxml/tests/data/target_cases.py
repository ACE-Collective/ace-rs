"""Writes target_cases.json: what lxml 6.1.3's target parser calls for hand-made and generated XML,
which crates/ace-lxml's target tests compare `target::parse` with.

Run it in ace3's dev container, which has lxml:

    docker exec -i ace-dev-1 /venv/bin/python3 -I - < crates/ace-lxml/tests/data/target_cases.py \\
        > crates/ace-lxml/tests/data/target_cases.json

Each case is bytes, written to a file and parsed as ace3's Office modules parse one,
`etree.parse(path, etree.XMLParser(target=...))`, and its answer the events, `start` with the tag and
its attributes in order, `end` with the tag, and the data between them joined, and whether the
parse raised. The error's text isn't kept: ace3's modules only log it.
"""

import base64
import gzip
import json
import os
import random
import sys
import tempfile

from lxml import etree


class Recorder:
    def __init__(self):
        self.events = []

    def start(self, tag, attrib):
        self.events.append(["start", tag, [[k, v] for k, v in attrib.items()]])

    def end(self, tag):
        self.events.append(["end", tag])

    def data(self, data):
        if self.events and self.events[-1][0] == "data":
            self.events[-1][1] += data
        else:
            self.events.append(["data", data])

    def close(self):
        return None


def run(data):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as fp:
        fp.write(data)
        path = fp.name
    recorder = Recorder()
    try:
        etree.parse(path, etree.XMLParser(target=recorder))
        raised = False
    except Exception:
        raised = True
    finally:
        os.unlink(path)
    return {"events": recorder.events, "raised": raised}


NS = b'xmlns:pkg="http://schemas.microsoft.com/office/2006/xmlPackage"'

HAND = [
    b"",
    b" ",
    b"<r/>",
    b"<r></r>",
    b"<?xml version='1.0'?><r>t</r>",
    b"<?xml version='1.0' encoding='UTF-8' standalone='yes'?>\n<r>t</r>\n",
    b"\xef\xbb\xbf<r>bom</r>",
    "<r>wide é</r>".encode("utf-16"),
    "<?xml version='1.0' encoding='UTF-16'?><r>wide</r>".encode("utf-16-le"),
    "<?xml version='1.0' encoding='UTF-16'?><r>wide</r>".encode("utf-16"),
    "<?xml version='1.0' encoding='ISO-8859-1'?><r>café</r>".encode("latin-1"),
    "<?xml version='1.0' encoding='ISO-8859-2'?><r>Ł</r>".encode("iso-8859-2"),
    b"<?xml version='1.0' encoding='US-ASCII'?><r>a</r>",
    b"<?xml version='1.0' encoding='bogus'?><r>a</r>",
    b"<?xml version='1.0' encoding='UTF-8'?><r>\xff</r>",
    b"<?xml version='1.1'?><r>v</r>",
    b"<?xml version='2.0'?><r>v</r>",
    b"<r a='1' b=\"2\" c='&amp;&lt;&gt;&apos;&quot;'/>",
    b"<r a='x\ty\nz\r\nw'/>",
    b"<r a='&#9;&#10;&#13;'/>",
    b"<r a='1' a='2'/>",
    b"<r xmlns='urn:d'><c/><p:c xmlns:p='urn:p' p:a='1' a='2'/></r>",
    b"<r xmlns='urn:d'><c xmlns=''/></r>",
    b"<r xml:lang='en' xml:space='preserve'>t</r>",
    b"<p:r/>",
    b"<r><p:c/></r>",
    b"<r xmlns:p='urn:p'><p:c><p:d>t</p:d></p:c></r>",
    b"<r>a<![CDATA[<b>&amp;]]>c</r>",
    b"<r><!-- c -->a<?pi x?>b</r>",
    b"<!-- before --><?pi?><r/><!-- after -->",
    b"<r>&#65;&#x42;&#x10FFFF;</r>",
    b"<r>&#0;</r>",
    b"<r>&#xD800;</r>",
    b"<r>&undefined;</r>",
    b"<!DOCTYPE r [<!ENTITY e 'v'>]><r>&e;</r>",
    b"<!DOCTYPE r [<!ENTITY e '<c>x</c>'>]><r>&e;&e;</r>",
    b"<!DOCTYPE r [<!ENTITY e 'a&amp;b'>]><r a='&e;'>&e;</r>",
    b"<!DOCTYPE r [<!ENTITY e SYSTEM 'file:///etc/hostname'>]><r>&e;<s/></r>",
    b"<!DOCTYPE r [<!ENTITY e SYSTEM 'http://example.com/x'>]><r>a&e;b</r>",
    b"<!DOCTYPE r [<!ENTITY % p SYSTEM 'file:///etc/hostname'>%p;]><r/>",
    b"<!DOCTYPE r [<!ENTITY % p '<!ENTITY q \"w\">'>%p;]><r>&q;</r>",
    b"<!DOCTYPE r SYSTEM 'x.dtd'><r>&x;<s/></r>",
    b"<!DOCTYPE r PUBLIC 'p' 'x.dtd'><r/>",
    b"<!DOCTYPE r [<!ATTLIST r a CDATA 'dflt'>]><r/>",
    b"<!DOCTYPE r [<!ATTLIST r xmlns:p CDATA 'urn:p'>]><r><p:c/></r>",
    b"<!DOCTYPE r [<!ENTITY a 'aaaaaaaaaa'><!ENTITY b '&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;'><!ENTITY c '&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;'><!ENTITY d '&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;'><!ENTITY e '&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;'><!ENTITY f '&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;'><!ENTITY g '&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;'>]><r>&g;</r>",
    b"<r><a>t</b></r>",
    b"<r><a>t</r>",
    b"<r>",
    b"<r/><r/>",
    b"<r/>junk",
    b"junk<r/>",
    b"<r>\x01</r>",
    b"<r><1/></r>",
    b"<r a=1/>",
    b"<r a='<'/>",
    b"<r>]]></r>",
    b"<r>a & b</r>",
    b"<r>" + b"x" * 20000 + b"</r>",
    b"<r a='" + b"x" * 20000 + b"'/>",
    b"<" + b"n" * 60000 + b"/>",
    b"<?xml version='1.0'?>\n<?mso-application progid=\"Word.Document\"?>\n<pkg:package " + NS + b"><pkg:part pkg:name='/a.bin'><pkg:binaryData>QUJD\nREVG</pkg:binaryData></pkg:part></pkg:package>",
    gzip.compress(b"<r>z</r>", mtime=0),
    gzip.compress(b"<r>z", mtime=0) + gzip.compress(b"</r>", mtime=0) + b"junk",
    gzip.compress(b"<r><a>1</a>" + b"<b>z</b>" * 2000 + b"</r>", mtime=0)[:200],
    b"\x1f\x8b<r/>",
    gzip.compress(b"<r>z</r>", mtime=0) + b"\x1f\x8bjunk",
]


def nested(depth, leaf=b"t"):
    return b"<a>" * depth + leaf + b"</a>" * depth


HAND += [nested(d) for d in (254, 255, 256, 257, 300)]


def generated(count, seed=7):
    rng = random.Random(seed)
    names = ["a", "b", "p:c", "w:t", "Relationship", "pkg:part", "x-y", "_z"]
    pieces = ["t", " ", "\n", "&amp;", "&#x41;", "<![CDATA[c]]>", "<!--c-->", "<?p?>", "é", "☃", "&e;"]
    cases = []
    for _ in range(count):
        depth = 0
        stack = []
        out = ["<?xml version='1.0'?>"] if rng.random() < 0.5 else []
        if rng.random() < 0.3:
            out.append("<!DOCTYPE r [<!ENTITY e 'ent'>]>")
        out.append("<r xmlns:p='urn:p' xmlns:w='urn:w' xmlns:pkg='urn:pkg'>")
        for _ in range(rng.randint(1, 30)):
            roll = rng.random()
            if roll < 0.35 and depth < 6:
                name = rng.choice(names)
                attrs = "".join(f" {rng.choice(['a', 'p:b', 'w:instr', 'Type', 'Target'])}{i}='{rng.choice(['v', '&amp;', ' x '])}'" for i in range(rng.randint(0, 2)))
                out.append(f"<{name}{attrs}>")
                stack.append(name)
                depth += 1
            elif roll < 0.6 and stack:
                out.append(f"</{stack.pop()}>")
                depth -= 1
            else:
                out.append(rng.choice(pieces))
        if rng.random() < 0.9:
            out.extend(f"</{name}>" for name in reversed(stack))
        out.append("</r>")
        text = "".join(out)
        if rng.random() < 0.1 and len(text) > 3:
            at = rng.randrange(len(text))
            text = text[:at] + text[at + 1:]
        cases.append(text.encode())
    return cases


cases = {}
for index, data in enumerate(HAND + generated(400)):
    cases[f"case_{index:04}"] = {"input": base64.b64encode(data).decode(), **run(data)}
json.dump(cases, sys.stdout, indent=0, sort_keys=True, ensure_ascii=True)
sys.stdout.write("\n")
