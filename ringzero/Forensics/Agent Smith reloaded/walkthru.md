# Agent Smith reloaded

## Challenge Details

- Category: Forensics
- Points: 4
- Validation: 312
- Author: Cedrick Chaput
- Status: Done
# Handout
`Agent Smith reloaded; Can you find the matrix password again?`
https://ringzer0ctf.com/files/2b4d08e1a1eac8a8c9034036d420bd88.zip
## Walkthrough
Unzipping:
```bash
$ unzip 2b4d08e1a1eac8a8c9034036d420bd88.zip
Archive:  2b4d08e1a1eac8a8c9034036d420bd88.zip
  inflating: BK
```
Let's identify what we are dealing with:
```bash
$ file BK
BK: Linux rev 1.0 ext3 filesystem data, UUID=ca014691-c6ea-4a5a-8da4-74a1aa1c9a80
```
A raw ext3 linux fs, again we could go autopsy, but, if it's solvable by sleuthkit why load such a heavy software, running fls for basic recon:
```bash
$ fls BK
d/d 11: lost+found
r/r 14: TODO.me
r/r * 12:       secret.sve
d/d 13: .hide
d/d 17: .ls
r/r * 16:       secret.odg
V/V 1281:       $OrphanFiles
```
and in the directories discovered
```bash
$ fls BK 11
(no output)

$ fls BK 13
r/r 15: secret.odg

$ fls BK 17
(no output)

$ fls BK 1281
(no output)
```
Okay, so we have:
TODO.me inode 14
secret.sve inode 12 which has been deleted, some sve format
secret.odg inode 15 in .hide folder, an open office drawing
secret.odg inode 16 which has been deleted
and a few empty dirs.

Let's start with TODO.me, as it has the best chance of giving us a hint as to what's going on:
```bash
$ icat BK 14
-cryt my password file with Secret Vault Encrypt
-bring back milk
-buy flower for my love !
-restric my my little brother permission to delete file.
```
Okay so the deleted files are probably important, and the sve stans for secret vault encrypt, some custom format which contains a password, which is presumably our flag. So, we need to recover what's in secret.sve, `icat` the remaining files the deleted files don't show (empty outputs on icat), but we can recover inode 15 secret.odg
```bash
$ icat BK 15 > secret.odg && file secret.odg
secret.odg: OpenDocument Drawing
```
Let's open it in libreoffice. As odg, and other office files are essentially zip files, we could also looking at zip contents if we're at a dead end.
![](attachments/1.png)
Yup, they're right it WOULD have been too easy. Let's look at the zip structure:
```bash
$ unzip -l secret.odg
Archive:  secret.odg
  Length      Date    Time    Name
---------  ---------- -----   ----
       43  2014-02-07 02:06   mimetype
     1126  2014-02-07 02:06   meta.xml
     9061  2014-02-07 02:06   settings.xml
     6540  2014-02-07 02:06   content.xml
     1462  2014-02-07 02:06   Thumbnails/thumbnail.png
        0  2014-02-07 02:06   Configurations2/images/Bitmaps/
        0  2014-02-07 02:06   Configurations2/popupmenu/
        0  2014-02-07 02:06   Configurations2/toolpanel/
        0  2014-02-07 02:06   Configurations2/statusbar/
        0  2014-02-07 02:06   Configurations2/progressbar/
        0  2014-02-07 02:06   Configurations2/toolbar/
        0  2014-02-07 02:06   Configurations2/floater/
        0  2014-02-07 02:06   Configurations2/menubar/
        0  2014-02-07 02:06   Configurations2/accelerator/current.xml
    19573  2014-02-07 02:06   styles.xml
      990  2014-02-07 02:06   META-INF/manifest.xml
---------                     -------
    38795                     16 files
```
This seems unlikely, nothing stands out to me, let's pivot back to the deleted files, they can definitely be recovered by using ext3grep for the deleted files at inodes: 12:secret.sve and 16:secret.odg , or analyzing the journal file:
```bash
$ ext3grep BK --inode 12
Running ext3grep version 0.10.2
No --ls used; implying --print.

WARNING: I don't know what EXT3_FEATURE_COMPAT_EXT_ATTR is.
Number of groups: 1
Loading group metadata... done
Minimum / maximum journal block: 198 / 1227
Loading journal descriptors... sorting... done
The oldest inode block that is still in the journal, appears to be from 1391736883 = Fri Feb  7 07:04:43 2014
Number of descriptors in journal: 252; min / max sequence numbers: 3 / 47

Hex dump of inode 12:
0000 | a4 81 00 00 00 00 00 00 c1 39 f4 52 1b 42 f4 52 | .........9.R.B.R
0010 | 1b 42 f4 52 1b 42 f4 52 00 00 00 00 00 00 00 00 | .B.R.B.R........
0020 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
0030 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
0040 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
0050 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
0060 | 00 00 00 00 a0 23 05 a6 cb 04 00 00 00 00 00 00 | .....#..........
0070 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................

Inode is Unallocated
Group: 0
Generation Id: 2785354656
uid / gid: 0 / 0
mode: rrw-r--r--
size: 0
num of links: 0
sectors: 0 (--> 0 indirect blocks).

Inode Times:
Accessed:       1391737281 = Fri Feb  7 07:11:21 2014
File Modified:  1391739419 = Fri Feb  7 07:46:59 2014
Inode Modified: 1391739419 = Fri Feb  7 07:46:59 2014
Deletion time:  1391739419 = Fri Feb  7 07:46:59 2014

Direct Blocks: 0


$ ext3grep BK --inode 16
Running ext3grep version 0.10.2
No --ls used; implying --print.

WARNING: I don't know what EXT3_FEATURE_COMPAT_EXT_ATTR is.
Number of groups: 1
Loading group metadata... done
Minimum / maximum journal block: 198 / 1227
Loading journal descriptors... sorting... done
The oldest inode block that is still in the journal, appears to be from 1391736883 = Fri Feb  7 07:04:43 2014
Number of descriptors in journal: 252; min / max sequence numbers: 3 / 47

Hex dump of inode 16:
0000 | b4 81 f4 01 00 00 00 00 d2 3f f4 52 9e 40 f4 52 | .........?.R.@.R
0010 | 9e 40 f4 52 9e 40 f4 52 f4 01 00 00 00 00 00 00 | .@.R.@.R........
0020 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
0030 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
0040 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
0050 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
0060 | 00 00 00 00 be 23 05 a6 cb 04 00 00 00 00 00 00 | .....#..........
0070 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................

Inode is Unallocated
Group: 0
Generation Id: 2785354686
uid / gid: 500 / 500
mode: rrw-rw-r--
size: 0
num of links: 0
sectors: 0 (--> 0 indirect blocks).

Inode Times:
Accessed:       1391738834 = Fri Feb  7 07:37:14 2014
File Modified:  1391739038 = Fri Feb  7 07:40:38 2014
Inode Modified: 1391739038 = Fri Feb  7 07:40:38 2014
Deletion time:  1391739038 = Fri Feb  7 07:40:38 2014

Direct Blocks: 0
```
As expected, ext3grep says the inode is unallocated, that's why icat failed to get the files as well. Let's retry to parse these from the journal file of the fs:
```bash
$ ext3grep BK --show-journal-inodes 12
Running ext3grep version 0.10.2
WARNING: I don't know what EXT3_FEATURE_COMPAT_EXT_ATTR is.
Number of groups: 1
Loading group metadata... done
Minimum / maximum journal block: 198 / 1227
Loading journal descriptors... sorting... done
The oldest inode block that is still in the journal, appears to be from 1391736883 = Fri Feb  7 07:04:43 2014
Number of descriptors in journal: 252; min / max sequence numbers: 3 / 47
Copies of inode 12 found in the journal:

--------------Inode 12 (transaction 44)------------------
Generation Id: 2785354656
uid / gid: 0 / 0
mode: rrw-r--r--
size: 0
num of links: 0
sectors: 0 (--> 0 indirect blocks).

Inode Times:
Accessed:       1391737281 = Fri Feb  7 07:11:21 2014
File Modified:  1391739419 = Fri Feb  7 07:46:59 2014
Inode Modified: 1391739419 = Fri Feb  7 07:46:59 2014
Deletion time:  1391739419 = Fri Feb  7 07:46:59 2014

Direct Blocks: 0

--------------Inode 12 (transaction 43)------------------
Generation Id: 2785354656
uid / gid: 0 / 0
mode: rrw-r--r--
size: 212
num of links: 1
sectors: 4 (--> 1 indirect block).

Inode Times:
Accessed:       1391737281 = Fri Feb  7 07:11:21 2014
File Modified:  1391737276 = Fri Feb  7 07:11:16 2014
Inode Modified: 1391736996 = Fri Feb  7 07:06:36 2014
Deletion time:  0

Direct Blocks: 1229

--------------Inode 12 (transaction 3)------------------
Generation Id: 2785354656
uid / gid: 0 / 0
mode: rrw-r--r--
size: 184
num of links: 1
sectors: 4 (--> 1 indirect block).

Inode Times:
Accessed:       1391736883 = Fri Feb  7 07:04:43 2014
File Modified:  1391736883 = Fri Feb  7 07:04:43 2014
Inode Modified: 1391736883 = Fri Feb  7 07:04:43 2014
Deletion time:  0

Direct Blocks: 1228


$ ext3grep BK --show-journal-inodes 16
Running ext3grep version 0.10.2
WARNING: I don't know what EXT3_FEATURE_COMPAT_EXT_ATTR is.
Number of groups: 1
Loading group metadata... done
Minimum / maximum journal block: 198 / 1227
Loading journal descriptors... sorting... done
The oldest inode block that is still in the journal, appears to be from 1391736883 = Fri Feb  7 07:04:43 2014
Number of descriptors in journal: 252; min / max sequence numbers: 3 / 47
Copies of inode 16 found in the journal:

--------------Inode 16 (transaction 44)------------------
Generation Id: 2785354686
uid / gid: 500 / 500
mode: rrw-rw-r--
size: 0
num of links: 0
sectors: 0 (--> 0 indirect blocks).

Inode Times:
Accessed:       1391738834 = Fri Feb  7 07:37:14 2014
File Modified:  1391739038 = Fri Feb  7 07:40:38 2014
Inode Modified: 1391739038 = Fri Feb  7 07:40:38 2014
Deletion time:  1391739038 = Fri Feb  7 07:40:38 2014

Direct Blocks: 0

--------------Inode 16 (transaction 40)------------------
Generation Id: 2785354686
uid / gid: 500 / 500
mode: rrw-rw-r--
size: 9526
num of links: 1
sectors: 22 (--> 1 indirect block).

Inode Times:
Accessed:       1391738834 = Fri Feb  7 07:37:14 2014
File Modified:  1391738807 = Fri Feb  7 07:36:47 2014
Inode Modified: 1391738807 = Fri Feb  7 07:36:47 2014
Deletion time:  0

Direct Blocks: 1230 1231 1232 1233 1234 1235 1236 1237 1238 1239

--------------Inode 16 (transaction 36)------------------
Generation Id: 0
uid / gid: 0 / 0
mode: ---------
size: 0
num of links: 0
sectors: 0 (--> 0 indirect blocks).

Inode Times:
Accessed:       0
File Modified:  0
Inode Modified: 0
Deletion time:  0

Direct Blocks: 0
```
Great! The journal has recoverable copies of these deleted files:
```text
inode 12 transaction 43: size 212, block 1229  
inode 12 transaction 3: size 184, block 1228  
inode 16 transaction 40: size 9526, blocks 1230-1239
```
Let's restore them
```bash
$ ext3grep BK --restore-inode 12
Running ext3grep version 0.10.2
WARNING: I don't know what EXT3_FEATURE_COMPAT_EXT_ATTR is.
Number of groups: 1
Minimum / maximum journal block: 198 / 1227
Loading journal descriptors... sorting... done
The oldest inode block that is still in the journal, appears to be from 1391736883 = Fri Feb  7 07:04:43 2014
Number of descriptors in journal: 252; min / max sequence numbers: 3 / 47
Writing output to directory RESTORED_FILES/
Restoring inode.12

$ ext3grep BK --restore-inode 16
Running ext3grep version 0.10.2
WARNING: I don't know what EXT3_FEATURE_COMPAT_EXT_ATTR is.
Number of groups: 1
Minimum / maximum journal block: 198 / 1227
Loading journal descriptors... sorting... done
The oldest inode block that is still in the journal, appears to be from 1391736883 = Fri Feb  7 07:04:43 2014
Number of descriptors in journal: 252; min / max sequence numbers: 3 / 47
Restoring inode.16

$ file RESTORED_FILES/*
RESTORED_FILES/inode.12: Zip archive data, made by v3.0 UNIX, extract using at least v2.0, last modified Feb 06 2014 20:33:02, uncompressed size 16, method=deflate
RESTORED_FILES/inode.16: OpenDocument Drawing
```
We got the files! The one at inode 12, `secret.sve` identified as a zip file, common for office documents. Let's first look at this odg file:
```bash
$ cp RESTORED_FILES/inode.16 RESTORED_FILES/secretdeleted.odg
```
It seems to be the exact same as before:
![](attachments/2.png)
Let's verify:
```bash
$ md5sum RESTORED_FILES/secretdeleted.odg secret.odg
6ae4c488e2ed80c961af0e1d7ecbb624  RESTORED_FILES/secretdeleted.odg
6ae4c488e2ed80c961af0e1d7ecbb624  secret.odg
```
Yup, they're the same file (unless they got an md5 collision somehow??) My main focus shifts to inode 12, it's probably another opendocument, but judging the name `Vault`, it's probably password protected. Running `unzip -l`
```bash
$ unzip -l RESTORED_FILES/inode.12
Archive:  RESTORED_FILES/inode.12
  Length      Date    Time    Name
---------  ---------- -----   ----
       16  2014-02-07 07:03   secret.txt
---------                     -------
       16                     1 file

$ unzip RESTORED_FILES/inode.12
Archive:  RESTORED_FILES/inode.12
[RESTORED_FILES/inode.12] secret.txt password:
```
I guess not, it's just our flag in a text file, but it is password protected, no worries we can get the hash using zip2john and crack using johntheripper:
```bash
$ zip2john RESTORED_FILES/inode.12 > secret.sve.hash && cat secret.sve.hash
ver 2.0 efh 5455 efh 7875 inode.12/secret.txt PKZIP Encr: TS_chk, cmplen=26, decmplen=16, crc=EE8F939A ts=A421 cs=a421 type=8
inode.12/secret.txt:$pkzip$1*1*2*0*1a*10*ee8f939a*0*44*8*1a*a421*bab041197a7d69df7197aa75bbb5fac22c908a0d999a2b85e162*$/pkzip$:secret.txt:inode.12::RESTORED_FILES/inode.12
```
Let's crack using rockyou and jtr:
```bash
$ john secret.sve.hash --wordlist=~/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 20 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
12345            (inode.12/secret.txt)
1g 0:00:00:00 DONE (2026-06-01 17:04) 25.00g/s 1024Kp/s 1024Kc/s 1024KC/s 123456..loser69
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
And there's our password: 12345, how anticlimactic. Let's get our flag:
```bash
$ unzip RESTORED_FILES/inode.12 && cat secret.txt
Archive:  RESTORED_FILES/inode.12
[RESTORED_FILES/inode.12] secret.txt password:
  inflating: secret.txt
FLAG-menummenum
```
And there's our flag!
# FLAG
FLAG-menummenum