import base64

basing = open("not_32_passwords.txt").read().splitlines()[-1].strip()

while True:
    try:
        basing = base64.b64decode(basing).decode().strip()
    except:
        print(basing)
        break
