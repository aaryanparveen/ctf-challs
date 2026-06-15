# Deleted file

## Challenge Details

- Category: Forensics
- Points: 5
- Validation: 14741
- Author: Manah
- Status: Done
# Handout
`Deleted file: You can look all you want, but this key is empty...`
`Your cousin found a USB drive in the library this morning. He’s not very good with computers, so he’s hoping you can find the owner of this stick! The flag is the owner’s identity in the form firstname_lastname`
https://static.root-me.org/forensic/ch39/ch39.gz

## Walkthrough
We are probably looking at a usb image, and we need to look at the exifdata for author for a deleted file.
Extracting:

```bash
$ tar -xvf ch39.gz
usb.image
```

Let's use sleuthkit fls and icat to look around for deleted files:

```bash
$ fls usb.image
r/r 3:  USB         (Volume Label Entry)
r/r * 5:        anonyme.png
v/v 1013699:    $MBR
v/v 1013700:    $FAT1
v/v 1013701:    $FAT2
V/V 1013702:    $OrphanFiles
```

There! anonyme.png at inode 5 was deleted, let's icat it
```bash
$ icat usb.image 5 > anonyme.png && file anonyme.png
anonyme.png: PNG image data, 400 x 300, 8-bit/color RGB, non-interlaced
```

Fortunately ( or unfortunately ) the deleted file was still recoverable from the fs metadata, so we dont have to look too deep into the journaling. Let's look at the exif data:
```bash
$ exiftool anonyme.png
ExifTool Version Number         : 13.50
File Name                       : anonyme.png
Directory                       : .
File Size                       : 246 kB
File Modification Date/Time     : 2026:06:13 22:59:56+05:30
File Access Date/Time           : 2026:06:13 22:59:56+05:30
File Inode Change Date/Time     : 2026:06:13 22:59:56+05:30
File Permissions                : -rwxrwxrwx
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 400
Image Height                    : 300
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Gamma                           : 2.2
White Point X                   : 0.3127
White Point Y                   : 0.329
Red X                           : 0.64
Red Y                           : 0.33
Green X                         : 0.3
Green Y                         : 0.6
Blue X                          : 0.15
Blue Y                          : 0.06
Background Color                : 255 255 255
XMP Toolkit                     : Image::ExifTool 11.88
Creator                         : Javier Turcot
Image Size                      : 400x300
Megapixels                      : 0.120
```

And that should be our flag! Creator: Javier Turcot
# FLAG
javier_turcot
