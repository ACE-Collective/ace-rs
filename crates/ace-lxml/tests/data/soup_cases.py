"""Writes soup_cases.json: BeautifulSoup 4.15.0's tree over lxml 6.1.3 for hand-made and generated
HTML, which crates/ace-lxml's soup tests compare `soup::parse` with.

Run it in ace3's dev container, which has both:

    docker exec -i ace-dev-1 /venv/bin/python3 -I - < crates/ace-lxml/tests/data/soup_cases.py \\
        > crates/ace-lxml/tests/data/soup_cases.json

Each case is bytes, decoded as ace3's HTML modules decode a file (`errors="ignore"`), and its
answer every node of the tree in document order: a tag's name, its attributes, its `.string` and
its first string child, or a string's kind and text. None for markup bs4 refuses.
"""

import base64
import json
import random
import sys
import warnings

import bs4

warnings.simplefilter("ignore")

CONTAINERS = {"Script", "Stylesheet", "TemplateString", "RubyTextString", "RubyParenthesisString"}
KINDS = {"NavigableString": "plain", "Comment": "comment", "ProcessingInstruction": "pi", "Doctype": "doctype"}

HAND = [
    b"",
    b" ",
    b"x",
    b"\x00",
    b"\xef\xbb\xbf<p>bom</p>",
    b"<!DOCTYPE html><html><head><title>t</title></head><body><p>a</p></body></html>",
    b'<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><p>x',
    b'<!DOCTYPE x SYSTEM "s.dtd"><p>x',
    b"<!DOCTYPE><p>x",
    b"<div><!--c-->text<b>x</b></div>",
    b"<p><!----></p>",
    b"<p>  </p><pre>  </pre><textarea>\n\n</textarea>",
    b'<p class="  a\xc2\xa0b   c " id=" x "> </p>',
    b'<a rel="x  y" rev="" href="h" class="">l</a><link rel="stylesheet icon"><td headers="a b">',
    b'<form accept-charset="utf-8 latin1"><object archive="a b"><area rel="r s"><icon sizes="1 2"><iframe sandbox="a b"><output for="x y">',
    b'<p accesskey="a b" dropzone="c d" CLASS="Up Per">',
    b'<p a=1 a=2 b=3 a=4>',
    b"<input disabled checked value>",
    b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><script xlink:href="x.js"></script><script href="y.js"/><script><![CDATA[ var a = 1; ]]></script></svg>',
    b"<script>var a = '<p>not a tag</p>';</script><script></script><script> </script>",
    b"<script type=\"application/json\">{\"a\": 1}</script><script type=\"TEXT/JavaScript\">alert(1)</script>",
    b"<style>p { color: red }</style><template><p>t</p></template><ruby>a<rt>b</rt><rp>(</rp></ruby>",
    b"<p>a<!-- c -->b<?php echo 1 ?>c</p>",
    b"<table><tr><td>1<td>2</table><p>after",
    b"<p><div>nested</div></p></p></p>",
    b"<b><i>x</b>y</i>z",
    b"<ul><li>a<li>b</ul>",
    b"&amp; &lt;b&gt; &nbsp; &#x41; &#65; &bogus;",
    b'<img src="a.png" onerror="alert(document.cookie)" onclick=\'go("x")\' ONLOAD="  f()  ">',
    b"<body onload=\"init()\"><div id=\"d\" data-x=\"https://evil.example.com/a\">payload</div></body>",
    b"<html><head><script src=\"a.js\"></script></head><body><script>window.location=\"x\"</script></body></html>",
    b"<p>caf\xc3\xa9 \xe2\x9c\x93 \xf0\x9f\x98\x80</p>",
    b"<p>bad \xff\xfe bytes \xc3</p>",
    b"<p>\x01\x02\x0b\x0c\x7f</p>",
    b"<x-custom foo=bar>c</x-custom><svg:rect/><o:p></o:p>",
    b"<p>a\r\nb\rc</p>",
    b"<frameset><frame src=x></frameset>",
    b"<noscript><p>n</p></noscript><noembed>e</noembed><xmp><b>x</b></xmp><plaintext><b>",
    b"<title><b>t</b></title><iframe><b>i</b></iframe>",
    b"text before<html>inside</html>text after",
    b"<head><meta charset=\"utf-8\"><meta http-equiv=\"content-type\" content=\"text/html; charset=latin1\"></head>",
    b"</p></div>stray end tags",
    b"<p>unterminated",
    b"<!-- unterminated comment",
    b"<a href='x'>one<a href='y'>two</a>",
    b"<select><option>a<option>b</select>",
    b"<math><mi>x</mi></math>",
    b"<p>" + b"<b>" * 300 + b"deep" + b"</b>" * 300 + b"</p>",
    b"<div>" * 300,
    b'{"log": {"entries": [{"text": "<script>alert(\\"x\\")</script>"}]}}',
]

PIECES = [
    "<p>", "</p>", "<div>", "</div>", "<b>", "</b>", "<script>", "</script>", "<style>", "</style>",
    "<!--", "-->", "<!-- c -->", "<![CDATA[", "]]>", "<svg>", "</svg>", "<template>", "</template>",
    "<pre>", "</pre>", "<table>", "<td>", "<tr>", "</table>", " ", "  ", "\n", "\t", "\r\n", "text",
    "café", " ", " ", "&amp;", "&lt;", "&#0;", "&#xD800;", "<", ">", "=", "\"", "'",
    '<a href="x" class=" a  b ">', '<img src=x onerror="go()">', '<script src="s.js">', '<p id=a id=b>',
    "<?x?>", "<!DOCTYPE html>", "<br/>", "<br>", "</br>", "<rt>", "<rp>", "<textarea>", "</textarea>",
    "\x00", "\x0c", "<html>", "</html>", "<body>", "</body>", "<head>", "</head>", "<title>", "<ruby>",
    '<div onclick="alert(1)" data-u="https://x.example/">', "<noscript>", "</noscript>", "<x:y>",
]


def generated(count):
    rng = random.Random(4)
    cases = []
    for _ in range(count):
        text = "".join(rng.choice(PIECES) for _ in range(rng.randint(1, 40)))
        data = text.encode("utf-8")
        if rng.random() < 0.15:
            at = rng.randrange(len(data) + 1)
            data = data[:at] + bytes([rng.choice([0x80, 0xc3, 0xff, 0xe2])]) + data[at:]
        cases.append(data)
    return cases


def kind_of(node):
    name = type(node).__name__
    if name in CONTAINERS:
        return "container"
    return KINDS.get(name, name)


def tree(text):
    try:
        soup = bs4.BeautifulSoup(text, "lxml")
    except Exception:
        return None
    nodes = []
    for node in soup.descendants:
        if isinstance(node, bs4.Tag):
            attrs = [[k, v if isinstance(v, str) else list(v)] for k, v in node.attrs.items()]
            string = node.string
            own = node.find(string=True, recursive=False)
            nodes.append({
                "tag": node.name,
                "attrs": attrs,
                "string": None if string is None else str(string),
                "own": None if own is None else str(own),
            })
        else:
            nodes.append({"kind": kind_of(node), "text": str(node)})
    return nodes


def main():
    cases = {}
    for index, data in enumerate(HAND):
        cases[f"hand_{index:03d}"] = data
    for index, data in enumerate(generated(700)):
        cases[f"gen_{index:03d}"] = data
    out = {}
    for name, data in cases.items():
        out[name] = {
            "input": base64.b64encode(data).decode(),
            "nodes": tree(data.decode("utf-8", errors="ignore")),
        }
    json.dump(out, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")


main()
