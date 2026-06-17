import base64
import itertools

key = b'66ec80c110f42039d7d0dcb3db5f43b7'
hacking = b'X1sVDEpEQ15CHEZGU15XVgkbREMdEE4TDhD1lWaF5bRgoRTBAXWUNVB1BbXlQVREYRVREGaDknKmAof2wxfmxzRV4YBVIDAQBsPkFvUVYcF1kQTGlCE0RCBR4CAE4XBk5...'

dcryption1 = ''.join(chr(c^k) for c,k in zip(base64.b64decode(hacking), itertools.cycle(key)))

#print(dcryption1)
with open("medusa_deobfuscated.py","w") as f:
    f.write(dcryption1)
