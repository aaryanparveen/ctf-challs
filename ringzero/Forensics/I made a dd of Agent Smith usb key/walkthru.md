# I made a dd of Agent Smith usb key

## Challenge Details

- Category: Forensics
- Points: 1
- Validation: 4027
- Author: Cedrick Chaput
- Status: Done
# Handout
`I'm sure it contain the matrix password! Can you find it?
https://ringzer0ctf.com/files/c32769969ef586f7e7c49b20bc5753fb.zip
## Walkthrough
Judging by the challenge name, we are probably dealing with a usb image file, we can easily verify it:
```bash
$ file 86b265d37d1fc10b721a2accae04a60d
86b265d37d1fc10b721a2accae04a60d: Linux rev 1.0 ext2 filesystem data (mounted or unclean), UUID=91c0fd20-bd3d-44e3-bfbb-1c18a9c0a20b
```
so it is indeed an fs, we could go open in autopsy but judging by the points it can probably be done by basic sleuthkit commands
```bash
$ fls 86b265d37d1fc10b721a2accae04a60d
d/d 11: lost+found
r/- * 0:        secret.txt
d/d 13: image
d/d 17: to keep
V/V 137:        $OrphanFiles

$ fls 86b265d37d1fc10b721a2accae04a60d  137
-/r * 12:       OrphanFile-12
-/r * 18:       OrphanFile-18
-/r * 19:       OrphanFile-19

$ fls 86b265d37d1fc10b721a2accae04a60d  13
r/r 14: 01.jpeg
r/r 15: 02.jpeg
r/r 16: 03.jpg

$ fls 86b265d37d1fc10b721a2accae04a60d  11
(no output)
```
seems inode 11 lost+found is empty, secret.txt marked with * means its deleted, and indeed there exist orphan files. Let's start there.
```bash
icat 86b265d37d1fc10b721a2accae04a60d  12
FLAG-ggmgk05096
```

and.. that's it.. I suppose?
As a sidenote, you could just do 

```bash
strings 86b265d37d1fc10b721a2accae04a60d | grep FLAG
```

but where's the fun in that :)
# FLAG
FLAG-ggmgk05096