"""Records ace3's is_image and _image_hash (Pillow 13.0.0) for every file of a directory.

Run in ace3's container: /venv/bin/python3 -I oracle.py <dir> > oracle.json
The two functions are copied from saq/modules/file_analysis/is_file_type.py and
saq/modules/dhash.py so that this runs without ace3's configuration. Pillow's registry is
brought to the state a long-running ace3 process has (preinit, then init), so the plugin
order does not depend on the first file's extension.
"""
import json, os, sys, warnings

warnings.filterwarnings("ignore")
from PIL import Image

Image.preinit()
Image.init()

IMAGE_SIZE = 16


def is_image(path) -> bool:
    try:
        with Image.open(path) as im:
            return True
    except OSError:
        return False
    except Exception:
        return False


def _image_hash(path: str) -> int:
    width = IMAGE_SIZE + 1
    with Image.open(path) as image:
        if image.mode in ("RGBA", "LA"):
            background = Image.new(image.mode[:-1], image.size, "white")
            background.paste(image, image.split()[-1])
            image = background
        grays = image.convert("L").resize((width, width), Image.Resampling.LANCZOS).tobytes()
    row_hash = 0
    col_hash = 0
    for y in range(IMAGE_SIZE):
        for x in range(IMAGE_SIZE):
            offset = y * width + x
            row_hash = row_hash << 1 | (grays[offset] < grays[offset + 1])
            col_hash = col_hash << 1 | (grays[offset] < grays[offset + width])
    return row_hash << (IMAGE_SIZE * IMAGE_SIZE) | col_hash


root = sys.argv[1]
out = {}
for name in sorted(os.listdir(root)):
    path = os.path.join(root, name)
    r = {"is_image": is_image(path)}
    try:
        with Image.open(path) as im:
            r["format"], r["mode"], r["size"] = im.format, im.mode, list(im.size)
    except Exception as e:
        r["open_error"] = type(e).__name__
    try:
        r["hash"] = format(_image_hash(path), "x")
    except Exception as e:
        r["error"] = {"type": type(e).__name__, "message": str(e)[:200]}
    out[name] = r
json.dump(out, sys.stdout, indent=0, sort_keys=True)
