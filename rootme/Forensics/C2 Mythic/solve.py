import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = base64.b64decode("DmVWKchtzpH0jA5/EXN2N5ORGwhYBGFdUBm7iel2r/0=")

def decrypt(message):
    message = base64.urlsafe_b64decode(message + b"=" * (-len(message) % 4))

    iv = message[36:52]
    ct = message[52:-32]

    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
    
print("--- get ---")
for line in open("get_messages.b64", "rb"):
    print(decrypt(line).decode())

print("\n--- post ---\n")   
for line in open("post_messages.b64", "rb"):
    print(decrypt(line).decode())

print("\n--- resp ---\n")
for line in open("resp_messages.b64", "rb"):
    print(decrypt(line).decode())
