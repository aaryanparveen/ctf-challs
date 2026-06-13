key = 0x18
encoded = b"{t~5ye{" 
decoded = bytearray() 
for b in encoded: 
	decoded.append(b ^ key) 
	key = (key + 1) & 0xff 
print(decoded.decode())
