from pathlib import Path
import numpy as np
from PIL import Image

dump = "paint/pid.2332.dmp"
out = Path("final")
out.mkdir(exist_ok=True)

off = 0xb0f0000  # offset for most probable flag location from image white canvas
bpp = 4         # color mode
wmin = 50
wmax = 1000

data = open(dump, "rb").read()[off:]

for w in range(wmin, wmax + 1):
    stride = w * bpp
    rows = len(data) // stride
    if rows < 2:
        continue

    raw = np.frombuffer(data[:rows * stride], dtype=np.uint8)
    a = raw.reshape(rows, w, bpp)

    rgb = a[:, :, [2, 1, 0]]

    white = (rgb >= 235).all(axis=2).mean(axis=1)
    dark = (rgb <= 40).all(axis=2).mean(axis=1)

    canvas = (white > 0.55) | ((white > 0.35) & (dark > 0.001))

    end = 0
    bad = 0

    for i, ok in enumerate(canvas):
        if ok:
            end = i + 1
            bad = 0
        else:
            bad += 1
            if bad >= 20 and end > 20:
                break

    if end < 20:
        continue

    img = rgb[:end]
    Image.fromarray(np.ascontiguousarray(img), "RGB").save(out / f"w{w}_h{end}.png")

print("please be done")
