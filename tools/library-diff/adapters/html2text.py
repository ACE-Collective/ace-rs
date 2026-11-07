"""html2text, as crates/ace-mod-msoffice's module calls it on an email's body: the file as UTF-8 text in
Python's text mode, ignoring what doesn't decode, which is ace3's `open(path, errors="ignore")` on a
UTF-8 locale. Every sample is a body as far as it's concerned, whatever it holds.
"""

from html2text import html2text


def run(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as fp:
        return html2text(fp.read())


def has_content(output):
    return bool(output.strip())
