"""Writes the test images for ace-dhash into a directory (argv[1]), with Pillow and by hand.

Run in ace3's container: /venv/bin/python3 -I gen.py /tmp/ace4-ace-dhash/cases
Every image is made here from seeded noise, gradients and shapes; nothing is copied in.
"""
import io, os, random, struct, sys, zlib
import numpy as np
from PIL import Image, ImageDraw

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
rng = random.Random(1234)
nrng = np.random.default_rng(1234)
written = {}


def put(name, data):
    assert name not in written, name
    written[name] = len(data)
    with open(os.path.join(out, name), "wb") as f:
        f.write(data)


def save(im, name, fmt, **kw):
    b = io.BytesIO()
    try:
        im.save(b, fmt, **kw)
    except Exception as e:
        print("skip", name, type(e).__name__, e, file=sys.stderr)
        return None
    put(name, b.getvalue())
    return b.getvalue()


def gradient(w, h, mode="RGB"):
    x = np.linspace(0, 255, w)[None, :].repeat(h, 0)
    y = np.linspace(0, 255, h)[:, None].repeat(w, 1)
    r = x.astype(np.uint8)
    g = y.astype(np.uint8)
    b = ((x + y) / 2).astype(np.uint8)
    im = Image.fromarray(np.dstack([r, g, b]), "RGB")
    return im if mode == "RGB" else im.convert(mode)


def noise(w, h, bands=3):
    a = nrng.integers(0, 256, size=(h, w, bands), dtype=np.uint8)
    if bands == 1:
        return Image.fromarray(a[:, :, 0], "L")
    return Image.fromarray(a, {3: "RGB", 4: "RGBA", 2: "LA"}[bands])


def shapes(w, h, mode="RGB", bg="white"):
    im = Image.new("RGB", (w, h), bg)
    d = ImageDraw.Draw(im)
    for i in range(12):
        x0, y0 = rng.randrange(w), rng.randrange(h)
        x1, y1 = x0 + rng.randrange(1, w), y0 + rng.randrange(1, h)
        c = (rng.randrange(256), rng.randrange(256), rng.randrange(256))
        if i % 3 == 0:
            d.ellipse((x0, y0, x1, y1), fill=c)
        elif i % 3 == 1:
            d.rectangle((x0, y0, x1, y1), fill=c)
        else:
            d.line((x0, y0, x1, y1), fill=c, width=3)
    return im if mode == "RGB" else im.convert(mode)


def rgba_varied(w, h):
    im = shapes(w, h)
    a = np.linspace(0, 255, w)[None, :].repeat(h, 0).astype(np.uint8)
    a[: h // 4] = 0
    a[h // 4 : h // 2] = 255
    im.putalpha(Image.fromarray(a, "L"))
    return im


def sources():
    """(name, image) pairs in many modes and sizes."""
    s = []
    for w, h in [(1, 1), (2, 3), (16, 16), (17, 17), (18, 18), (33, 7), (100, 75), (257, 129)]:
        s.append((f"grad{w}x{h}", gradient(w, h)))
    s.append(("noise64", noise(64, 64)))
    s.append(("noise200x150", noise(200, 150)))
    s.append(("shapes320x240", shapes(320, 240)))
    s.append(("shapes31x400", shapes(31, 400)))
    s.append(("shapes400x31", shapes(400, 31)))
    s.append(("rgba120x90", rgba_varied(120, 90)))
    s.append(("noisea50", noise(50, 50, 4)))
    return s


SRC = sources()
BIG = gradient(3000, 2000)
BIGSHAPES = shapes(2400, 1800)

# ---------------------------------------------------------------- PNG via Pillow
for name, im in SRC:
    save(im, f"png_{name}_rgb.png", "PNG")
for name, im in SRC[::2]:
    for mode in ("1", "L", "LA", "P", "RGBA", "I;16", "I"):
        conv = im.convert(mode) if mode != "I;16" else im.convert("L").convert("I;16")
        save(conv, f"png_{name}_{mode.replace(';', '')}.png", "PNG")
p = SRC[10][1].convert("P", palette=Image.Palette.ADAPTIVE, colors=16)
save(p, "png_p16_trns.png", "PNG", transparency=3)
save(p, "png_p16_trnsbytes.png", "PNG", transparency=bytes([0, 128, 255, 10] + [255] * 12))
save(SRC[10][1].convert("L"), "png_l_trns.png", "PNG", transparency=40)
save(SRC[10][1], "png_rgb_trns.png", "PNG", transparency=(255, 255, 255))
save(rgba_varied(300, 200), "png_rgba300.png", "PNG")
save(BIG, "png_big3000x2000.png", "PNG", compress_level=9)
save(BIGSHAPES.convert("P"), "png_bigshapes_p.png", "PNG", optimize=True)
for i, lvl in enumerate([0, 1, 6]):
    save(SRC[9][1], f"png_level{lvl}.png", "PNG", compress_level=lvl)
# APNG: the first frame is what is hashed
frames = [shapes(80, 60) for _ in range(3)]
save(frames[0], "apng3.png", "PNG", save_all=True, append_images=frames[1:])
save(frames[0].convert("RGBA"), "apng_rgba.png", "PNG", save_all=True, append_images=[f.convert("RGBA") for f in frames[1:]], default_image=True)


# ---------------------------------------------------------------- PNG by hand
def chunk(cid, data):
    return struct.pack(">I", len(data)) + cid + data + struct.pack(">I", zlib.crc32(cid + data) & 0xFFFFFFFF)


def png_raw(w, h, depth, ctype, rows, interlace=0, plte=None, trns=None, extra=b"", level=6, filt=None):
    """rows: bytes of each (sub)image line without filter byte; filter types chosen per line."""
    raw = b""
    for i, r in enumerate(rows):
        f = (filt if filt is not None else i) % 5
        raw += bytes([f]) + png_filter(f, r, rows[i - 1] if i and not interlace else None, depth, ctype)
    ihdr = struct.pack(">IIBBBBB", w, h, depth, ctype, 0, 0, interlace)
    b = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
    if plte is not None:
        b += chunk(b"PLTE", plte)
    if trns is not None:
        b += chunk(b"tRNS", trns)
    b += extra + chunk(b"IDAT", zlib.compress(raw, level)) + chunk(b"IEND", b"")
    return b


CH = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


def png_filter(f, row, prev, depth, ctype):
    bpp = max(1, CH[ctype] * depth // 8)
    prev = prev or bytes(len(row))
    out = bytearray(len(row))
    for i in range(len(row)):
        a = row[i - bpp] if i >= bpp else 0
        b = prev[i]
        c = prev[i - bpp] if i >= bpp else 0
        if f == 0:
            p = 0
        elif f == 1:
            p = a
        elif f == 2:
            p = b
        elif f == 3:
            p = (a + b) // 2
        else:
            pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
            p = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
        out[i] = (row[i] - p) & 255
    return bytes(out)


for depth, ctype in [(1, 0), (2, 0), (4, 0), (8, 0), (16, 0), (8, 2), (16, 2), (1, 3), (2, 3), (4, 3), (8, 3), (8, 4), (16, 4), (8, 6), (16, 6)]:
    w, h = 37, 23
    rowbytes = (w * CH[ctype] * depth + 7) // 8
    rows = [bytes(rng.randrange(256) for _ in range(rowbytes)) for _ in range(h)]
    plte = bytes(rng.randrange(256) for _ in range(3 * (1 << depth))) if ctype == 3 else None
    put(f"pnghand_{depth}_{ctype}.png", png_raw(w, h, depth, ctype, rows, plte=plte))
# filters on a smooth image
w, h = 50, 40
rows = [bytes((x * 3 + y * 5 + (x * y) % 7) & 255 for x in range(w * 3)) for y in range(h)]
for f in range(5):
    put(f"pnghand_filter{f}.png", png_raw(w, h, 8, 2, rows, filt=f))
put("pnghand_badfilter.png", png_raw(w, h, 8, 2, rows, filt=None).replace(b"IDAT", b"IDAT"))


# interlaced PNG by hand (Adam7)
def adam7(w, h, depth, ctype, pix):
    """pix: function (x, y) -> bytes of one pixel (depth >= 8) or int sample (depth < 8)."""
    passes = [(0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)]
    raw = b""
    for x0, y0, dx, dy in passes:
        xs = list(range(x0, w, dx))
        if not xs:
            continue
        prev = None
        for y in range(y0, h, dy):
            if depth >= 8:
                row = b"".join(pix(x, y) for x in xs)
            else:
                bits = "".join(format(pix(x, y), f"0{depth}b") for x in xs)
                bits += "0" * (-len(bits) % 8)
                row = bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))
            f = (y // dy) % 5
            raw += bytes([f]) + png_filter(f, row, prev, depth, ctype)
            prev = row
    ihdr = struct.pack(">IIBBBBB", w, h, depth, ctype, 0, 0, 1)
    plte = b"".join(bytes([i * 17 % 256, i * 31 % 256, i * 47 % 256]) for i in range(256))
    b = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
    if ctype == 3:
        b += chunk(b"PLTE", plte[: 3 * (1 << depth)])
    return b + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


for w, h in [(1, 1), (3, 2), (9, 9), (33, 21)]:
    put(f"pngi_rgb_{w}x{h}.png", adam7(w, h, 8, 2, lambda x, y: bytes([(x * 7) & 255, (y * 9) & 255, (x * y) & 255])))
    put(f"pngi_rgba_{w}x{h}.png", adam7(w, h, 8, 6, lambda x, y: bytes([(x * 7) & 255, (y * 9) & 255, (x * y) & 255, (x * 40) & 255])))
    put(f"pngi_p2_{w}x{h}.png", adam7(w, h, 2, 3, lambda x, y: (x + y) % 4))
    put(f"pngi_l1_{w}x{h}.png", adam7(w, h, 1, 0, lambda x, y: (x ^ y) & 1))
    put(f"pngi_l16_{w}x{h}.png", adam7(w, h, 16, 0, lambda x, y: struct.pack(">H", (x * 1000 + y * 77) & 0xFFFF)))
    put(f"pngi_la8_{w}x{h}.png", adam7(w, h, 8, 4, lambda x, y: bytes([(x * 11) & 255, (y * 50) & 255])))

# ---------------------------------------------------------------- GIF
for name, im in SRC[::2]:
    save(im, f"gif_{name}.gif", "GIF")
save(SRC[1][1].convert("L"), "gif_l.gif", "GIF")
save(SRC[10][1], "gif_interlaced.gif", "GIF", interlace=True)
save(p, "gif_trns.gif", "GIF", transparency=2)
save(rgba_varied(64, 48), "gif_rgba.gif", "GIF")
gframes = [shapes(64, 64).convert("P") for _ in range(3)]
save(gframes[0], "gif_anim.gif", "GIF", save_all=True, append_images=gframes[1:], duration=100, loop=0)
save(BIGSHAPES.convert("P"), "gif_big.gif", "GIF")
save(Image.new("1", (40, 30), 1), "gif_1bit.gif", "GIF")

# ---------------------------------------------------------------- BMP
for name, im in SRC[::2]:
    save(im, f"bmp_{name}.bmp", "BMP")
for mode in ("1", "L", "P", "RGBA"):
    save(SRC[9][1].convert(mode), f"bmp_shapes_{mode}.bmp", "BMP")
save(SRC[10][1].convert("RGB"), "dib_shapes.dib", "DIB")


def bmp_file(w, h, bits, pixels, palette=b"", comp=0, header=40, masks=b"", topdown=False):
    hh = struct.pack("<IiiHHIIiiII", header, w, -h if topdown else h, 1, bits, comp, len(pixels), 2835, 2835, len(palette) // 4, 0)
    hh += masks
    hh += b"\0" * (header - len(hh)) if header > len(hh) else b""
    off = 14 + len(hh) + len(palette)
    return b"BM" + struct.pack("<IHHI", off + len(pixels), 0, 0, off) + hh + palette + pixels


def rows_bmp(w, h, bpp, f):
    stride = ((w * bpp + 31) >> 3) & ~3
    out = b""
    for y in range(h):
        r = f(y)
        out += r + b"\0" * (stride - len(r))
    return out


w, h = 21, 13
put("bmp16_555.bmp", bmp_file(w, h, 16, rows_bmp(w, h, 16, lambda y: b"".join(struct.pack("<H", (x * 1500 + y * 3) & 0x7FFF) for x in range(w)))))
put("bmp16_565.bmp", bmp_file(w, h, 16, rows_bmp(w, h, 16, lambda y: b"".join(struct.pack("<H", (x * 2100 + y * 77) & 0xFFFF) for x in range(w))), comp=3, masks=struct.pack("<III", 0xF800, 0x7E0, 0x1F)))
put("bmp32_bitfields_bgra.bmp", bmp_file(w, h, 32, rows_bmp(w, h, 32, lambda y: b"".join(bytes([x * 10 & 255, y * 15 & 255, 77, x * 12 & 255]) for x in range(w))), comp=3, header=56, masks=struct.pack("<IIII", 0xFF0000, 0xFF00, 0xFF, 0xFF000000)))
put("bmp32_raw.bmp", bmp_file(w, h, 32, rows_bmp(w, h, 32, lambda y: b"".join(bytes([x * 10 & 255, y * 15 & 255, 77, 0]) for x in range(w)))))
put("bmp24_topdown.bmp", bmp_file(w, h, 24, rows_bmp(w, h, 24, lambda y: b"".join(bytes([x * 10 & 255, y * 15 & 255, 200]) for x in range(w))), topdown=True))
pal4 = b"".join(bytes([i * 16, 255 - i * 16, i * 7, 0]) for i in range(16))
put("bmp4.bmp", bmp_file(w, h, 4, rows_bmp(w, h, 4, lambda y: bytes(((x * 2 + y) & 15) << 4 | ((x * 2 + 1 + y) & 15) for x in range((w + 1) // 2))), palette=pal4))
pal8 = b"".join(bytes([i, (i * 3) & 255, (i * 7) & 255, 0]) for i in range(256))
gray8 = b"".join(bytes([i, i, i, 0]) for i in range(256))
put("bmp8_gray.bmp", bmp_file(w, h, 8, rows_bmp(w, h, 8, lambda y: bytes((x * 9 + y) & 255 for x in range(w))), palette=gray8))
# RLE8 and RLE4
rle8 = b""
for y in range(h):
    rle8 += bytes([5, y * 10 & 255, 0, 4, 1, 2, 3, 4, 3, 77]) + b"\0\0"
rle8 += b"\0\1"
put("bmp_rle8.bmp", bmp_file(w, h, 8, rle8, palette=pal8, comp=1))
put("bmp_rle8_delta.bmp", bmp_file(w, h, 8, bytes([3, 9, 0, 2, 4, 2, 6, 50, 0, 0, 2, 7]) + b"\0\1", palette=pal8, comp=1))
rle4 = b""
for y in range(h):
    rle4 += bytes([7, 0x1F, 0, 5, 0x12, 0x34, 0x50, 0]) + b"\0\0"
rle4 += b"\0\1"
put("bmp_rle4.bmp", bmp_file(w, h, 4, rle4, palette=pal4, comp=2))
put("bmp_rle8_short.bmp", bmp_file(w, h, 8, bytes([5, 1, 5, 2]), palette=pal8, comp=1))
put("bmp_core12.bmp", b"BM" + struct.pack("<IHHI", 0, 0, 0, 26) + struct.pack("<IHHHH", 12, 4, 2, 1, 24) + bytes(range(24)))
put("bmp_v5.bmp", bmp_file(w, h, 24, rows_bmp(w, h, 24, lambda y: b"".join(bytes([x * 10 & 255, y * 15 & 255, 1]) for x in range(w))), header=124))

# ---------------------------------------------------------------- ICO / CUR
save(SRC[11][1], "ico_shapes.ico", "ICO", sizes=[(16, 16), (32, 32), (48, 48)])
save(rgba_varied(64, 64), "ico_rgba.ico", "ICO", sizes=[(64, 64), (32, 32)])
save(shapes(256, 256), "ico_256.ico", "ICO", sizes=[(256, 256)], bitmap_format="bmp")
save(SRC[9][1].convert("P"), "ico_p.ico", "ICO", sizes=[(24, 24)], bitmap_format="bmp")

# ---------------------------------------------------------------- PPM family
for name, im in SRC[::3]:
    save(im, f"ppm_{name}.ppm", "PPM")
    save(im.convert("L"), f"pgm_{name}.pgm", "PPM")
    save(im.convert("1"), f"pbm_{name}.pbm", "PPM")
save(SRC[5][1].convert("I"), "pgm16.pgm", "PPM")
put("ppm_p1.pbm", b"P1\n# comment\n5 3\n1 0 1 0 1\n0 1 0 1 0\n1 1 1 0 0\n")
put("ppm_p2.pgm", b"P2\n4 2\n15\n0 3 7 15\n15 7 3 0\n")
put("ppm_p3.ppm", b"P3\n2 2\n255\n255 0 0  0 255 0\n0 0 255  255 255 255\n")
put("ppm_p2_maxval1000.pgm", b"P2\n3 1\n1000\n0 500 1000\n")
put("ppm_p5_maxval100.pgm", b"P5\n4 1\n100\n" + bytes([0, 50, 100, 101]))
put("ppm_p6_16.ppm", b"P6\n2 1\n65535\n" + struct.pack(">6H", 0, 1000, 65535, 300, 30000, 9))
put("pfm.pfm", b"Pf\n3 2\n-1.0\n" + struct.pack("<6f", 0.0, 0.5, 1.0, 100.0, 300.0, -5.0))
save(SRC[5][1].convert("F"), "pfm_pillow.pfm", "PPM")

# ---------------------------------------------------------------- TIFF
for name, im in SRC[::3]:
    for comp in ("raw", "tiff_lzw", "tiff_deflate", "packbits", "tiff_adobe_deflate"):
        save(im, f"tiff_{name}_{comp}.tif", "TIFF", compression=comp)
for mode in ("1", "L", "P", "RGBA", "CMYK", "I;16", "I", "F", "LA"):
    im = SRC[9][1].convert(mode) if mode != "I;16" else SRC[9][1].convert("L").convert("I;16")
    for comp in ("raw", "tiff_lzw", "packbits", "tiff_deflate"):
        if mode in ("I", "F") and comp == "packbits":
            continue
        save(im, f"tiff_mode{mode.replace(';', '')}_{comp}.tif", "TIFF", compression=comp)
save(SRC[9][1], "tiff_lzw_pred.tif", "TIFF", compression="tiff_lzw", tiffinfo={317: 2})
save(SRC[9][1], "tiff_deflate_pred.tif", "TIFF", compression="tiff_deflate", tiffinfo={317: 2})
save(BIGSHAPES.convert("P"), "tiff_big_lzw.tif", "TIFF", compression="tiff_lzw")
save(SRC[9][1].convert("YCbCr"), "tiff_ycbcr.tif", "TIFF")
save(SRC[9][1], "tiff_g4.tif", "TIFF", compression="tiff_lzw", tiffinfo={278: 16})
save(SRC[9][1].convert("1"), "tiff_ccitt_g4.tif", "TIFF", compression="group4")
save(SRC[9][1], "tiff_jpeg.tif", "TIFF", compression="jpeg")

# ---------------------------------------------------------------- WebP
for name, im in SRC[::2]:
    save(im, f"webp_{name}_lossless.webp", "WEBP", lossless=True)
    for q in (10, 50, 90):
        save(im, f"webp_{name}_q{q}.webp", "WEBP", quality=q)
save(rgba_varied(120, 90), "webp_rgba_lossless.webp", "WEBP", lossless=True)
save(rgba_varied(120, 90), "webp_rgba_lossy.webp", "WEBP", quality=70)
save(BIGSHAPES, "webp_big.webp", "WEBP", quality=80)
save(frames[0], "webp_anim.webp", "WEBP", save_all=True, append_images=frames[1:], duration=100)

# ---------------------------------------------------------------- JPEG
jsrc = [SRC[6][1], SRC[9][1], SRC[10][1], SRC[11][1], SRC[13][1].convert("RGB"), SRC[7][1], SRC[0][1], SRC[3][1]]
for i, im in enumerate(jsrc):
    for q in (5, 30, 75, 95, 100):
        for sub in (0, 1, 2):
            save(im, f"jpeg_{i}_q{q}_s{sub}.jpg", "JPEG", quality=q, subsampling=sub)
for i, im in enumerate(jsrc[:4]):
    save(im, f"jpeg_{i}_prog.jpg", "JPEG", quality=80, progressive=True)
    save(im, f"jpeg_{i}_opt.jpg", "JPEG", quality=80, optimize=True)
    save(im.convert("L"), f"jpeg_{i}_gray.jpg", "JPEG", quality=80)
    save(im.convert("CMYK"), f"jpeg_{i}_cmyk.jpg", "JPEG", quality=80)
    save(im, f"jpeg_{i}_restart.jpg", "JPEG", quality=80, restart_marker_blocks=2)
    save(im, f"jpeg_{i}_restartrows.jpg", "JPEG", quality=60, restart_marker_rows=1, subsampling=2)
save(BIG, "jpeg_big.jpg", "JPEG", quality=85)
save(BIGSHAPES, "jpeg_bigshapes_prog.jpg", "JPEG", quality=70, progressive=True)
ex = Image.Exif()
ex[0x0112] = 6
save(SRC[9][1], "jpeg_exif_orient6.jpg", "JPEG", exif=ex.tobytes())
save(SRC[9][1], "png_exif_orient6.png", "PNG", exif=ex.tobytes())

# ---------------------------------------------------------------- other Pillow writers
for fmt, ext, modes in [
    ("TGA", "tga", ("L", "P", "RGB", "RGBA")),
    ("PCX", "pcx", ("1", "L", "P", "RGB")),
    ("SGI", "sgi", ("L", "RGB", "RGBA")),
    ("QOI", "qoi", ("RGB", "RGBA")),
    ("IM", "im", ("L", "P", "RGB", "1", "I", "F")),
    ("MSP", "msp", ("1",)),
    ("XBM", "xbm", ("1",)),
    ("SPIDER", "spider", ("F",)),
    ("DDS", "dds", ("RGB", "RGBA", "L", "LA")),
    ("BLP", "blp", ("P", "RGBA")),
    ("ICNS", "icns", ("RGBA",)),
    ("EPS", "eps", ("RGB",)),
    ("JPEG2000", "jp2", ("RGB",)),
    ("AVIF", "avif", ("RGB",)),
]:
    for mode in modes:
        im = SRC[9][1].convert(mode)
        if fmt == "ICNS":
            im = shapes(64, 64).convert("RGBA")
        try:
            save(im, f"other_{ext}_{mode}.{ext}", fmt)
        except Exception as e:
            print("skip", fmt, mode, e, file=sys.stderr)
save(SRC[9][1], "other_tga_rle.tga", "TGA", compression="tga_rle")
save(SRC[9][1].convert("RGBA"), "other_tga_rle_rgba.tga", "TGA", compression="tga_rle")

# ---------------------------------------------------------------- not images, and magic-only
put("text.txt", b"hello world\n" * 10)
put("empty1.bin", b"\0")
put("zeros.bin", bytes(4096))
put("random.bin", rng.randbytes(5000))
put("html.html", b"<html><body>hi</body></html>")
put("pdf.pdf", b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n")
put("zip.zip", b"PK\x03\x04" + bytes(40))
magics = [b"BM", b"GIF89a", b"\xff\xd8\xff", b"P6", b"\x89PNG\r\n\x1a\n", b"II*\x00", b"MM\x00*", b"RIFF\0\0\0\0WEBPVP8 ", b"\0\0\1\0", b"\0\0\2\0", b"8BPS", b"qoif", b"DDS ", b"%!PS", b"SIMPLE", b"icns", b"\xd7\xcd\xc6\x9a\0\0", b"\x01\x00\x00\x00", b"#define", b"/* XPM */", b"BLP1", b"BLP2", b"\x0a\x05\x01\x08", b"\x01\xda", b"Y\xa6j\x95", b"DanM", b"\x80\xe8\x00\x00", b"\x00\x00\x01\xb3", b"BUFR", b"GRIB\0\0\0\1", b"\x89HDF\r\n\x1a\n", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"\xff\x4f\xff\x51", b"\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a", b"\0\0\0\x1cftypavif", b"Image type: ", b"im\x00\x00", b"FTEX", b"\0\0\0\0\0\0\0\4", b"P7 332\n"]
for i, m in enumerate(magics):
    put(f"magic_{i}_short.bin", m)
    put(f"magic_{i}_junk.bin", m + rng.randbytes(200))
    put(f"magic_{i}_zeros.bin", m + bytes(200))

# ---------------------------------------------------------------- truncated and corrupted
mrng = random.Random(99)
bases = sorted(n for n, size in written.items() if size <= 40000 and not n.startswith(("magic_", "text", "empty", "zeros", "random", "html", "pdf", "zip")))
by_prefix = {}
for n in bases:
    by_prefix.setdefault(n.split("_")[0], []).append(n)
picked = []
for k, names in sorted(by_prefix.items()):
    picked += mrng.sample(names, min(len(names), 6))
for n in picked:
    with open(os.path.join(out, n), "rb") as f:
        data = f.read()
    stem, ext = os.path.splitext(n)
    for frac in (0.02, 0.1, 0.5, 0.9, 0.99):
        cut = max(1, int(len(data) * frac))
        put(f"mut_{stem}_trunc{int(frac * 100)}{ext}", data[:cut])
    put(f"mut_{stem}_trunc_last{ext}", data[:-1])
    for i in range(6):
        b = bytearray(data)
        for _ in range(1 + i % 3):
            pos = mrng.randrange(len(b))
            b[pos] ^= 1 << mrng.randrange(8)
        put(f"mut_{stem}_flip{i}{ext}", bytes(b))
    b = bytearray(data)
    pos = mrng.randrange(len(b))
    b[pos:pos + 16] = bytes(mrng.randrange(256) for _ in range(16))
    put(f"mut_{stem}_junk{ext}", bytes(b))

# a declared size over the decompression bomb limit, and one between the limits
def png_header_only(w, h):
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(b"\0" * 10)) + chunk(b"IEND", b"")
put("bomb_png_error.png", png_header_only(20000, 20000))
put("bomb_png_warn.png", png_header_only(10000, 10000))
put("bomb_gif.gif", b"GIF89a" + struct.pack("<HH", 65535, 65535) + b"\0\0\0,\0\0\0\0\xff\xff\xff\xff\0\x08\x02\x4c\x01\0;")
put("bomb_bmp.bmp", bmp_file(30000, 30000, 24, b""))
put("bomb_jpeg.jpg", b"\xff\xd8\xff\xc0\x00\x11\x08\xff\xff\xff\xff\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01\xff\xd9")

print(len(written), sum(written.values()), file=sys.stderr)
