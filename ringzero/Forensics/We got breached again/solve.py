import re
from datetime import datetime
from urllib.parse import unquote
from collections import defaultdict

queries = []
flagbits = defaultdict(lambda: defaultdict(dict))

sqlcomm = re.compile(
    r"SUBSTRING\(REVERSE\(CONV\(HEX\(SUBSTRING\("
    r"\((.*?)\),(\d+),1\)\),16,2\)\),(\d+),1\)=1,SLEEP\(2\)"
)

for line in open("access.log", errors="ignore"):
    line = unquote(line)
    line = re.sub(r"/\*.*?\*/", "", line)

    m = sqlcomm.search(line)
    if not m:
        continue

    time_text = re.search(r"\[(.*?)\]", line).group(1)
    time = datetime.strptime(time_text, "%d/%b/%Y:%H:%M:%S %z")

    sql = m.group(1)
    i = int(m.group(2))
    bi = int(m.group(3))

    queries.append((time, sql, i, bi))

for n in range(len(queries) - 1):
    time, sql, i, bi = queries[n]
    next_time = queries[n + 1][0]

    sleeptime = (next_time - time).total_seconds()

    flagbits[sql][i][bi] = sleeptime >= 2

for sql in flagbits:
    print(sql)

    flag = ""

    for i in range(1, max(flagbits[sql]) + 1):
        c = 0

        for bi in range(1, 8):
            c += flagbits[sql][i].get(bi, 0) << (bi - 1)

        if c:
            flag += chr(c)

    print(flag)
    print()
