"""Seal a file as ace3's email archive seals an email (saq/email_archive/local.py: gzip, then
saq.crypto's encrypt), for the encrypted_archive_analyzer fixtures under fixtures/email_archive/.
It runs on ace3's Python in its dev container, reading the file on stdin and writing the sealed
bytes to stdout:

    docker exec -i -e PYTHONDONTWRITEBYTECODE=1 ace-dev-1 /venv/bin/python3 /tmp/ace4-dumps/seal.py \\
        KEY_HEX [--v1] [--no-gzip] < IN > OUT

ace3 writes v0 for its email archive; --v1 writes the layout its CAS writes, and --no-gzip seals the
bytes as they are, which then fail to gunzip.
"""

import gzip
import io
import sys

sys.path.insert(0, "/opt/ace")

from saq.crypto import FORMAT_V0, FORMAT_V1, encrypt_stream  # noqa: E402


def main():
    key = bytes.fromhex(sys.argv[1])
    data = sys.stdin.buffer.read()
    if "--no-gzip" not in sys.argv:
        buffer = io.BytesIO()
        # ace3's gzip.open(path, "wb") names the member after the file and stamps its mtime; the
        # fixture keeps neither, which gunzip doesn't read
        with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as fp:
            fp.write(data)
        data = buffer.getvalue()
    out = io.BytesIO()
    encrypt_stream(io.BytesIO(data), out, size=len(data), password=key,
                   format_version=FORMAT_V1 if "--v1" in sys.argv else FORMAT_V0)
    sys.stdout.buffer.write(out.getvalue())


if __name__ == "__main__":
    main()
