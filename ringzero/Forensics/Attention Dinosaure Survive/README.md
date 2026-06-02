# Attention Dinosaure Survive

## Challenge Details

- Category: Forensics
- Points: 2
- Validation: 1692
- Author: PRL
- Status: Done
# Handout
`Attention Dinosaure Survive; Dinosaure Survive`
https://ringzer0ctf.com/files/c7afb12d982f3683cc3b27233869157d.zip
## Walkthrough

Ominous name without a direct giveaway in the challenge name?! For a 2 pointer?! I guess we'll have to actually solve this one.
As usual first step is to unzip the handout file:
```bash
unzip c7afb12d982f3683cc3b27233869157d.zip
Archive:  c7afb12d982f3683cc3b27233869157d.zip
  inflating: 0b02119984a7cee0ba83d55425b9491f.E01
```
Ah, we are dealing with a disk image, eo1 is a disk image format used by encase. We can verify using file:
```bash
$ file 0b02119984a7cee0ba83d55425b9491f.E01
0b02119984a7cee0ba83d55425b9491f.E01: EWF/Expert Witness/EnCase image file format
```
We could use autopsy, but for 2 points.. sleuthkit should be just fine.
```bash
 fls 0b02119984a7cee0ba83d55425b9491f.E01
r/r 4-128-4:    $AttrDef
r/r 8-128-2:    $BadClus
r/r 8-128-1:    $BadClus:$Bad
r/r 6-128-4:    $Bitmap
r/r 7-128-1:    $Boot
d/d 11-144-4:   $Extend
r/r 2-128-1:    $LogFile
r/r 0-128-1:    $MFT
r/r 1-128-1:    $MFTMirr
d/d 35-144-1:   $RECYCLE.BIN
r/r 9-128-8:    $Secure:$SDS
r/r 9-144-11:   $Secure:$SDH
r/r 9-144-14:   $Secure:$SII
r/r 10-128-1:   $UpCase
r/r 3-128-3:    $Volume
d/d 39-144-1:   1
d/d 41-144-1:   2
d/d 43-144-1:   3
d/d 46-144-1:   4
d/d 48-144-1:   5
d/d 57-144-1:   System Volume Information
V/V 256:        $OrphanFiles
```
Well 5 directories, let's start there

```bash
$ fls 0b02119984a7cee0ba83d55425b9491f.E01 39-144-1
r/r 40-128-4:   dinosaur_park99.pdf

$ fls 0b02119984a7cee0ba83d55425b9491f.E01 41-144-1
r/r 42-128-4:   dinosaur-12.jpg

$ fls 0b02119984a7cee0ba83d55425b9491f.E01 43-144-1
r/r 44-128-3:   dppmapv2.pdf
r/r 45-128-4:   I-love-you-dinosaur-31000.png

$ fls 0b02119984a7cee0ba83d55425b9491f.E01 46-144-1
r/r 47-128-4:   Dinosaure.txt
r/r 47-128-7:   Dinosaure.txt:flag.txt

$ fls 0b02119984a7cee0ba83d55425b9491f.E01 48-144-1
r/r 49-128-4:   keep-calm-and-love-dinosaurs-21.png
```
flag.txt no kidding, lets icat that file at inode 47-128-7. flag.txt is hidden inside Dinosaure.txt as an alternate data stream, would have been fun to mount this and find it.. but nothing hides from sleuthkit! (so far)
```bash
$ icat 0b02119984a7cee0ba83d55425b9491f.E01 47-128-7
flag-6b96e212b3f85968db654f7892f06122
```
too bad we won't get to solve the actual mystery here either.. but hey that's our flag!

# FLAG
flag-6b96e212b3f85968db654f7892f06122