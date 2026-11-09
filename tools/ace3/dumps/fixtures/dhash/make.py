import os, sys, random
from PIL import Image, ImageDraw
out = sys.argv[1]
os.makedirs(f"{out}/images", exist_ok=True); os.makedirs(f"{out}/analyst_data/dhash", exist_ok=True)
rnd = random.Random(5)
def logo(shift=0, color=(200, 30, 30)):
    im = Image.new("RGB", (120, 80), "white"); d = ImageDraw.Draw(im)
    d.rectangle([10 + shift, 10, 60 + shift, 70], fill=color); d.ellipse([70, 15 + shift, 110, 65 + shift], fill=(20, 20, 160))
    d.line([0, 79, 119, 0], fill=(0, 120, 0), width=3); return im
logo().save(f"{out}/analyst_data/dhash/brand.png"); open(f"{out}/analyst_data/dhash/brand.png.score", "w").write("90\n")
noise = Image.new("L", (64, 64)); noise.putdata([rnd.randrange(256) for _ in range(64 * 64)])
noise.save(f"{out}/analyst_data/dhash/noise.png"); open(f"{out}/analyst_data/dhash/noise.png.score", "w").write("75.5")
logo(color=(10, 200, 10)).save(f"{out}/analyst_data/dhash/no_score.png")
open(f"{out}/analyst_data/dhash/not_an_image.png", "wb").write(b"not a png")
open(f"{out}/analyst_data/dhash/not_an_image.png.score", "w").write("50")
open(f"{out}/analyst_data/dhash/readme.txt", "w").write("ignored\n")
logo().save(f"{out}/images/brand_copy.png")
logo(shift=4).save(f"{out}/images/brand_shifted.png")
logo().save(f"{out}/images/brand.jpg", quality=85)
logo().convert("P", palette=Image.ADAPTIVE).save(f"{out}/images/brand.gif")
rgba = logo().convert("RGBA"); px = rgba.load()
for x in range(120):
    for y in range(80):
        if px[x, y][:3] == (255, 255, 255): px[x, y] = (0, 0, 0, 0)
rgba.save(f"{out}/images/brand_transparent.png")
noise.resize((200, 200)).save(f"{out}/images/noise_big.png")
Image.new("RGB", (300, 200), (90, 90, 90)).save(f"{out}/images/gray.bmp")
data = open(f"{out}/images/brand_copy.png", "rb").read(); open(f"{out}/images/truncated.png", "wb").write(data[: len(data) // 2])
open(f"{out}/images/not_image.png", "wb").write(b"\x89PNG but not really")
