import xml.etree.ElementTree as ET

root = ET.parse("notsosafe.xml").getroot()

with open("passwords.txt", "w") as p:
    for entry in root.iter("Entry"):
        for string in entry.findall("String"):
            if string.findtext("Key") == "Password":
                password = string.findtext("Value", "")
                if password:
                    p.write(password + "\n")

print("all your passwords are belong to us")
