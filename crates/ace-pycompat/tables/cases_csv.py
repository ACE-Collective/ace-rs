# Cases for csv: csv.reader(io.StringIO(text)), read on past errors as the iterator allows.
# Output: tests/data/csv.json.

import csv
import io

assert csv.field_size_limit() == 131072


def read(text):
    items = []
    errors = 0
    r = csv.reader(io.StringIO(text))
    while True:
        try:
            row = next(r)
        except StopIteration:
            break
        except Exception as e:
            items.append({"err": err(e)})
            errors += 1
            if errors == 4:
                break
            continue
        items.append({"row": row})
    return {"text": text, "items": items}


PIECES = [",", ",", '"', '"', '""', "\n", "\r", "\r\n", "\n\n", "\x00", " ", "a", "bc", "http://x.y/z", "\t", ";",
          "\x85", "\u2028", "\x0b", "\x0c", "\x1c"]

texts = ["", "\n", "\r", "\r\n", "a", "a,b", "a,b\n", "a,b\r\n", "a\rb", "a\r\nb", '"a\nb"', '"a""b"', '"a"b', '"a" b,c',
         '"open', '"open\n', 'a,"', '",', '"\r"', '"\r\n"\r\n', "\x00", "a\x00,b", ",,", ",\n,", "\n\n\n",
         "x" * 131072, "x" * 131073, '"' + "x" * 131072 + '"', '"' + "x" * 131073 + '"', "x" * 131073 + "\nok\n",
         '"' + "y" * 70000 + "\n" + "y" * 70000 + '"\nnext', "a\rb\nc,d\n\re\n", "a\r\rb"]
HEAD = len(texts)
while len(texts) < 6000:
    n = rng.randrange(0, 30)
    parts = []
    for _ in range(n):
        if rng.random() < 0.7:
            parts.append(rng.choice(PIECES))
        else:
            parts.append(random_string(6))
    texts.append("".join(parts))

dump(sample([read(t) for t in texts], HEAD))
