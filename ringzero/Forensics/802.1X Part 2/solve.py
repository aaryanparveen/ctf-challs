from scapy.all import rdpcap, EAPOL, raw
import hmac
import hashlib

PCAP = "e02d87707841f558986b78537e7c3ddc.pcap"
FRAME = 89

KCK = bytes.fromhex("e236939a002bb2a6f7d1cca7a542ae5c")

packets = rdpcap(PCAP)

e = raw(packets[FRAME - 1][EAPOL])

e = e[:4 + int.from_bytes(e[2:4], "big")]

target_mic = e[81:97] # or e236939a002bb2a6f7d1cca7a542ae5c from before

# we need to zero the mic field before recalculating
zeroed = e[:81] + b"\x00" * 16 + e[97:]

full_hmac = hmac.new(KCK, zeroed, hashlib.sha1).digest()
calculated = full_hmac[:16]

print("target MIC :", target_mic.hex())
print("calc MIC   :", calculated.hex())
print("not idiot?      :", calculated == target_mic)
