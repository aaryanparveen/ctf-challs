import hashlib

bingo    = "ea5f206d267a1d04abc09b446b94d573"
username = "133700"
realm    = "montreal.voip.ms"
nonce    = "1fdad2c4"
method   = "INVITE"
uri      = "sip:5145551337@montreal.voip.ms;transport=TCP"
#wordlist= "/home/hyp3rnov4/wordlists/rockyou.txt"
wordlist = "/mnt/d/ctf/Hashes.org"
def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


with open(wordlist, errors="ignore") as wl:
    for passwd in wl:
        passwd = passwd.strip()

        ha1 = md5(f"{username}:{realm}:{passwd}")
        ha2 = md5(f"{method}:{uri}")
        response = md5(f"{ha1}:{nonce}:{ha2}")

        if response == bingo:
            print("FIN.", passwd)
            break

    else:
        print("not found????")
