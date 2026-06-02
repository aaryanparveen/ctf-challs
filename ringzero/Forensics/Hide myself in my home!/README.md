# Hide myself in my home!

## Challenge Details

- Category: Forensics
- Points: 2
- Validation: 1858
- Author: Cedrick Chaput
- Status: Done
# Handout
https://ringzer0ctf.com/files/68789bfba0a2a675cab56db26e5d5bba.zip

## Walkthrough
Let's unzip the archive:
```bash
$ unzip 68789bfba0a2a675cab56db26e5d5bba.zip
Archive:  68789bfba0a2a675cab56db26e5d5bba.zip
  inflating: .viminfo
  inflating: .bash_profile
 extracting: bob.tar.gz
  inflating: .bashrc
 extracting: .bash_logout
   creating: .mozilla/
   creating: .mozilla/extensions/
   creating: .mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/
  inflating: .mozilla/extensions/{ec8030f7-c20a-464f-9b0e-13a3a9e97384}/.fedora-langpack-install
   creating: .mozilla/plugins/
  inflating: index.html
  inflating: .bash_history
  inflating: 1601066_559677267463652_942103441_n.jpg
  inflating: Electro - Swing || Jamie Berry Ft. Octavia Rose - Delight.mp3
   creating: .gnome2/
  inflating: you
  inflating: .me.swp
```
Okay, so this is a user's home directory.. I guess the title makes sense. 

Let's first look at the swap file
```bash
$ file .me.swp
.me.swp: Vim swap file, version 7.2, pid 13545, user test, host grosse-marde, file ~test/me, modified
```
It's a vim swapfile! (who could've guessed) Let's first create an empty file in the path that vim expects it and then lets recover it (or we could just cat it.. but that's boring and unclean)
```bash
$ mkdir ~test && touch ~test/me && vim -r .me.swp
$ cat ~test/me
i'm beautifull
and sunfull and
full of full


Flag-1s4g76jk89f
```
![image 20260529224707](attachments/1.png)
and there's our flag!
# FLAG
Flag-1s4g76jk89f
