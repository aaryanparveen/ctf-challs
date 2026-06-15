from hashlib import sha256  
from Crypto.Cipher import AES  
from Crypto.Util.Padding import unpad  
  
cipher_password = "mcsTnTld1dDn"  
  
key = sha256(cipher_password.encode("utf-8")).digest()  
iv = b"\x00" * 16  
  
encoded = open("Confidentiel.jpg.enc", "rb").read()  
  
cipher = AES.new(key, AES.MODE_CBC, iv)  
plain = unpad(cipher.decrypt(encoded), 16)  
  
open("Confidentiel.jpg", "wb").write(plain)

print("Sophisticated malware reversing complete.") 
