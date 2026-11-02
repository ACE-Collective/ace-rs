"""Write the extension ace3 gives each mime type, for the email module's unnamed parts.

ace3 names an unnamed MIME part `<email>.unknown_<type>_<subtype>_<NNN><ext>`, where ext is
`mimetypes.guess_extension(content_type)` (saq/modules/email/rfc822.py). That answer depends on
Python's built-in table and on /etc/mime.types in ace3's image, so this asks ace3's Python:

    docker exec -i ace-dev-1 /venv/bin/python3 - < tools/ace3/dumps/mime_extensions.py \\
        > crates/ace-mod-email/src/extensions.tsv

It writes one `<mime type>\\t<extension>` line per type that has an extension, sorted.
"""

import mimetypes

mimetypes.init()
types = set(mimetypes.types_map.values()) | set(mimetypes.common_types.values())
for mime_type in sorted(types):
    extension = mimetypes.guess_extension(mime_type)
    if extension:
        print(f"{mime_type}\t{extension}")
