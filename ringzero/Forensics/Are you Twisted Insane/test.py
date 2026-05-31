import hashlib

def md5(s):
    return hashlib.md5(s.encode()).hexdigest()

password = "test"

ha1 = md5("133700:montreal.voip.ms:" + password)
ha2 = md5("INVITE:sip:5145551337@montreal.voip.ms;transport=TCP")
resp = md5(ha1 + ":1fdad2c4:" + ha2)

print("HA1", ha1)
print("HA2", ha2)
print("RESP", resp)
