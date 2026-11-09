# The character classes of validators 0.36.0's regexes, each matched with re.IGNORECASE as the
# validators compile them, decided per code point by Python's re. Output: src/tables/regex_classes.rs.

import re

header("regex_classes.py")

CLASSES = [
    ("URL_USER_FIRST", r"[\u0100-\u017f\u0180-\u024f]", "validators.url's username regex, first alternative."),
    ("URL_USER_ATOM", r"[-!#$%&'*+/=?^_`{}|~0-9a-z]", "validators.url's username regex, second alternative."),
    ("URL_USER_QUOTED", r"[\001-\010\013\014\016-\037!#-\[\]-\177]", "validators.url's username regex, third alternative."),
    ("URL_PATH", r"[\/a-z0-9\-\.\_\~\!\$\&\'\(\)\*\+\,\;\=\:\@\%"
     + r"\U0001F300-\U0001F5FF"
     + r"\U0001F600-\U0001F64F"
     + r"\u00a0-\ud7ff\uf900-\ufdcf\ufdf0-\uffef]", "validators.url's path regex."),
    ("URL_FRAGMENT", r"[0-9a-z?/:@\-._~%!$&'()*+,;=#]", "validators.url's fragment regex."),
    ("HOST_ALNUM", r"[a-z0-9]", "validators.hostname's simple hostname regex, `[a-z0-9]`."),
    ("HOST_ALNUM_HYPHEN", r"[a-z0-9-]", "validators.hostname's simple hostname regex, `[a-z0-9-]`."),
    ("EMAIL_FIRST", r"[\u0100-\u017f\u0180-\u024f\u00a0-\u00ff]", "validators.email's username regex, first alternative."),
    ("EMAIL_ATOM", r"[\u0100-\u017f\u0180-\u024f\u00a0-\u00ff0-9a-z!#$%&'*+/=?^_`{}|~\-]",
     "validators.email's username regex, second alternative."),
    ("EMAIL_QUOTED", r"[\u0100-\u017f\u0180-\u024f\u00a0-\u00ff\001-\010\013\014\016-\037!#-\[\]-\177]",
     "validators.email's username regex, third alternative."),
]

for name, pattern, doc in CLASSES:
    rx = re.compile(pattern, re.IGNORECASE)
    emit_ranges(name, ranges(lambda cp: rx.fullmatch(chr(cp)) is not None), doc + " `%s` with re.IGNORECASE." % pattern.replace("`", "'"))
