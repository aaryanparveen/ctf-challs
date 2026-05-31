import re
import requests
from concurrent.futures import ThreadPoolExecutor

cdx = "https://web.archive.org/cdx?url=ringzer0team.com*&from=2013&to=2018&output=json&fl=timestamp,original&filter=statuscode:200"
rows = requests.get(cdx).json()[1:]

def check(row):
    ts, url = row
    archived = f"https://web.archive.org/web/{ts}id_/{url}"
    text = requests.get(archived, timeout=15).text
    low = text.lower()

    if "evilcorp" in low or "flag-" in low:
        print("\nGotcha:", archived)

        for flag in re.findall(r"FLAG-[A-Za-z0-9]+", text, re.I):
            print(flag)

with ThreadPoolExecutor(max_workers=20) as pool:
    list(pool.map(check, rows))