import hmac
import hashlib

pmk = bytes.fromhex("5f765b0403478e2da4520fe5332089654bbb18cb3d363828d5ee3b16438d7cc1")

ap = bytes.fromhex("000b867e2169")
s = bytes.fromhex("100ba96b6198")

anonce = bytes.fromhex("2a64108836acfd7e60591d27456a82753568e2b83d09bf8cd2e6588b8222b9da")
snonce = bytes.fromhex("a80162851db8432564ef0a1846a24e1fb313eb9a9ab9f24c03e5f7b39a592ded")

data = min(ap, s) + max(ap, s) + min(anonce, snonce) + max(anonce, snonce)

ptk = b""
i = 0

while len(ptk) < 64:
    ptk += hmac.new(
        pmk,
        b"Pairwise key expansion" + b"\x00" + data + bytes([i]),
        hashlib.sha1
    ).digest()
    i += 1

ptk = ptk[:64]
kck = ptk[:16]

print("PTK:", ptk.hex())
print("KCK:", kck.hex())
