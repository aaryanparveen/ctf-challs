import re

flaghits = open("flag_hits.txt", "r").read()

vals = {}

for pos, n in re.findall(r',\s*(\d+),1\)\)>\s*(\d+)\s*was\s+not\s+found', flaghits):
    pos = int(pos)
    n = int(n)

    if pos not in vals or n < vals[pos]:
        vals[pos] = n


flag = "".join(chr(vals[i]) for i in range(1, max(vals) + 1))
print(flag)
