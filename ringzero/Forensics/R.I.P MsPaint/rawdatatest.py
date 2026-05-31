from pathlib import Path
from PIL import Image

inp = Path("paint/pid.2332.dmp")   
width = 600                        # we don't know this! i can't find a solution other than the one in solve2.py
mode = "BGRA"                      # 4 bytes per pixel, can also try 3 for rgb but paint stores it in memory like this, we might also have to flip the image later but this is just a test

data = inp.read_bytes()

bpp = 4
part_size = len(data) // 4

imgs = []

for i in range(4):
    chunk = data[i * part_size:(i + 1) * part_size]

    height = len(chunk) // (width * bpp)
    chunk = chunk[:width * height * bpp]

    img = Image.frombuffer(
        "RGBA",
        (width, height),
        chunk,
        "raw",
        mode,
        0,
        1
    ).convert("RGB")

    imgs.append(img)

out = Image.new("RGB", (width * 4, imgs[0].height), "black")

for i, img in enumerate(imgs):
    out.paste(img, (i * width, 0))

out.save(f"rawtest.png")
print(f"saved")
