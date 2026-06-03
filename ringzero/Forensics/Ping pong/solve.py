import re

m = {}

text = open("mapping.txt").read()

for block in re.findall(r"beginbfchar(.*?)endbfchar", text, re.S):
    for a, b in re.findall(r"<(.*?)>\s*<(.*?)>", block):
        m[int(a, 16)] = chr(int(b, 16))

for block in re.findall(r"beginbfrange(.*?)endbfrange", text, re.S):
    for a, b, c in re.findall(r"<(.*?)>\s*<(.*?)>\s*<(.*?)>", block):
        a, b, c = int(a, 16), int(b, 16), int(c, 16)
        for x in range(a, b + 1):
            m[x] = chr(c + x - a)

codes = re.findall(r"<(.*?)>", open("cidcodes").read())

print("".join(m[int(x, 16)] for x in codes))
