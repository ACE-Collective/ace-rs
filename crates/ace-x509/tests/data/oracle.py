"""Records what ace3 answers for each case gen_corpus.py wrote, for ace-x509's tests.

Run in ace3's dev container (ace-dev-1), with a fixed hash seed so frozenset order is stable:
  PYTHONHASHSEED=0 /venv/bin/python3 -I oracle.py CASES.json OUT.json

For each case it records is_pem_bytes and is_der_bytes of the first 8192 bytes, is_x509 (on a
temporary file, as ace3 calls it), load_cert, and for a loaded certificate every value
x509_analyzer reads, each as {"ok": value} or {"err": [exception class, message]}, plus the
metadata file's text from the analyzer's steps in its order.
"""

import base64
import json
import os
import sys
import tempfile
import warnings

sys.path.insert(0, "/opt/ace")
warnings.simplefilter("ignore")


from saq import x509 as sx  # noqa: E402
from saq.modules.file_analysis.is_file_type import is_x509  # noqa: E402
from saq.modules.x509 import X509Analysis  # noqa: E402


def exc(e):
    t = type(e)
    name = t.__qualname__ if t.__module__ == "builtins" else f"{t.__module__}.{t.__qualname__}"
    return [name, str(e)]


def run(f, *a):
    try:
        return {"ok": f(*a)}
    except Exception as e:
        return {"err": exc(e)}


def dt(d):
    return {"str": str(d), "strftime": d.strftime("%Y-%m-%dT%H:%M:%S.%f%z")}


def analyze(cert):
    """X509Analyzer.execute_analysis's reads, in its order, and the metadata it writes."""
    analysis = X509Analysis()
    analysis.issuer = sx.issuer(cert)
    analysis.subject = sx.subject(cert)
    analysis.serial_number = sx.serial_number(cert)
    analysis.not_valid_before = sx.not_valid_before(cert)
    analysis.not_valid_after = sx.not_valid_after(cert)
    analysis.common_name = sx.common_name(cert)
    analysis.sha256_hash = sx.sha256(cert)
    for ip in sx.san_ip_addresses(cert):
        analysis.add_san_ip_address(ip)
    for name in sx.san_dns_names(cert):
        analysis.add_san_dns_name(name)
    analysis.extension_tree = sx.get_readable_extensions(cert)
    return json.dumps(analysis.details, default=str)


def main():
    cases = json.load(open(sys.argv[1]))
    out = []
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "f")
    for case in cases:
        data = base64.b64decode(case["b64"])
        head = data[:8192]
        r = {"name": case["name"], "b64": case["b64"]}
        r["is_pem"] = sx.is_pem_bytes(head)
        try:
            r["is_der"] = sx.is_der_bytes(head)
        except Exception as e:
            r["is_der"] = False
            r["is_der_exception"] = exc(e)
        with open(path, "wb") as f:
            f.write(data)
        r["is_x509"] = run(is_x509, path)
        loaded = run(sx.load_cert, data)
        if "err" in loaded:
            r["load"] = loaded
            out.append(r)
            continue
        cert = loaded["ok"]
        r["load"] = {"ok": cert is not None}
        if cert is not None:
            r["issuer"] = run(sx.issuer, cert)
            r["subject"] = run(sx.subject, cert)
            r["serial"] = str(cert.serial_number)
            r["not_before"] = run(lambda: dt(cert.not_valid_before_utc))
            r["not_after"] = run(lambda: dt(cert.not_valid_after_utc))
            r["common_name"] = run(sx.common_name, cert)
            r["sha256"] = sx.sha256(cert)
            r["san_ip"] = run(sx.san_ip_addresses, cert)
            r["san_dns"] = run(sx.san_dns_names, cert)
            r["extensions"] = sx.get_readable_extensions(cert)
            r["metadata"] = run(analyze, cert)
        out.append(r)
    json.dump(out, open(sys.argv[2], "w"))
    print(len(out), "cases")


main()
