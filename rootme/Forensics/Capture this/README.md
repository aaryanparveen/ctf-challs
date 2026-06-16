# Capture this

## Challenge Details

- Category: Forensics
- Points: 15
- Validation: 4556
- Author: Zey_Roxx
- Status: TODO
# Handout
`Capture this: Oh a screenshot.`
`An employee has lost his Keepass password. He couldn’t remember it, and couldn’t find his password file. After hours of searching, it turns out that he has sent a screen of his passwords to one of his colleagues, but it’s still nowhere to be found. He’s asking for your help to find him. It’s up to you`
https://static.root-me.org/forensic/ch42/ch42.zip

## Walkthrough
Unzipping:
```bash
$ unzip ch42.zip
Archive:  ch42.zip
  inflating: Capture.png
 extracting: Database.kdbx
```

I'm guessing the password won't be simply in rockyou, or this challenge would have a lot many more solves. Looking at Capture.png, we can't directly see a password, but something is cutoff on the M column of the excel sheet, so the image might have extra data, but because of the IHDR chunk width height / other image metadata, it's being cropped out.

![Capture](Capture.png)


# FLAG
TODO
