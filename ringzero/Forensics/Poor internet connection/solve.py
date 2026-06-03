import zipfile

brokenzip = zipfile.ZipFile("output/zip/00002159.zip")

#print(brokenzip.namelist())

flag = brokenzip.read("flag.txt", pwd=b"ZipYourMouth") # from tcp stream 1 flag.txt
print(flag.decode())
