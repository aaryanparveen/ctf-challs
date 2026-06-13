# Command & Control - level 3

## Challenge Details

- Category: Forensics
- Points: 30
- Validation: 12804
- Author: Thanat0s
- Status: TODO
# Handout
`Command & Control - level 3: Memory analysis; Berthier, the antivirus software didn’t find anything. It’s up to you now. Try to find the malware in the memory dump. The validation flag is the md5 checksum of the full path of the executable.`
https://static.root-me.org/forensic/ch2/ch2.tbz2
## Walkthrough
It's the same dump from level 2, so our volatility patch should continue working. We need to find md5 of the path of the executable. Let's start by looking at pslist psscan pstree output for anything suspicious 
```bash
$ vol -f ch2.dmp windows.psscan > psscan.txt
$ vol -f ch2.dmp windows.pstree > pstree.txt
$ vol -f ch2.dmp windows.pslist > pslist.txt
```

I didn't find anything obviously suspicious in psscan / pstree, no obvious "virus.exe":

```bash
$ cat psscan.txt
Volatility 3 Framework 2.28.0

PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

2168    468     conhost.exe     0xe506b0        2       49      1       False   2013-01-12 16:55:50.000000 UTC  N/A     Disabled
1136    2548    iexplore.exe    0xa47f678       18      454     1       False   2013-01-12 16:57:44.000000 UTC  N/A     Disabled
3556    3544    soffice.bin     0xaee2d18       0       -       1       False   2013-01-12 16:41:05.000000 UTC  2013-01-12 16:41:39.000000 UTC  Disabled
336     560     wlms.exe        0xc5267e0       4       45      0       False   2013-01-12 16:39:21.000000 UTC  N/A     Disabled
1232    2548    taskmgr.exe     0xc5fbc18       6       116     1       False   2013-01-12 16:42:29.000000 UTC  N/A     Disabled
1612    560     TPAutoConnSvc.  0x1c059030      9       135     0       False   2013-01-12 16:39:23.000000 UTC  N/A     Disabled
1712    560     spoolsv.exe     0x1d6f9c40      14      338     0       False   2013-01-12 16:38:58.000000 UTC  N/A     Disabled
1748    560     svchost.exe     0x1d702748      18      310     0       False   2013-01-12 16:38:58.000000 UTC  N/A     Disabled
1968    560     vmtoolsd.exe    0x1d7d84e0      6       220     0       False   2013-01-12 16:39:14.000000 UTC  N/A     Disabled
448     560     VMUpgradeHelpe  0x1d7f5030      4       89      0       False   2013-01-12 16:39:21.000000 UTC  N/A     Disabled
3624    560     svchost.exe     0x1d91d3e8      14      348     0       False   2013-01-12 16:41:22.000000 UTC  N/A     Disabled
3352    560     svchost.exe     0x1d93d2c0      9       141     0       False   2013-01-12 16:40:58.000000 UTC  N/A     Disabled
832     560     svchost.exe     0x1de05420      19      435     0       False   2013-01-12 16:38:23.000000 UTC  N/A     Disabled
904     560     svchost.exe     0x1de52918      17      409     0       False   2013-01-12 16:38:24.000000 UTC  N/A     Disabled
928     560     svchost.exe     0x1de6b030      26      869     0       False   2013-01-12 16:38:24.000000 UTC  N/A     Disabled
1084    560     svchost.exe     0x1de911a8      10      257     0       False   2013-01-12 16:38:26.000000 UTC  N/A     Disabled
1616    2772    cmd.exe 0x1de98030      2       101     1       False   2013-01-12 16:55:49.000000 UTC  N/A     Disabled
1220    560     AvastSvc.exe    0x1dea7868      66      1180    0       False   2013-01-12 16:38:28.000000 UTC  N/A     Disabled
1172    560     svchost.exe     0x1deb2790      15      475     0       False   2013-01-12 16:38:27.000000 UTC  N/A     Disabled
2900    560     SearchIndexer.  0x1defbb18      13      636     0       False   2013-01-12 16:40:38.000000 UTC  N/A     Disabled
2744    2548    StikyNot.exe    0x1defe8c0      8       135     1       False   2013-01-12 16:40:32.000000 UTC  N/A     Disabled
560     456     services.exe    0x1e0294c0      6       205     0       False   2013-01-12 16:38:16.000000 UTC  N/A     Disabled
692     560     svchost.exe     0x1e02f030      10      353     0       False   2013-01-12 16:38:21.000000 UTC  N/A     Disabled
584     456     lsm.exe 0x1e02f7e8      10      142     0       False   2013-01-12 16:38:16.000000 UTC  N/A     Disabled
576     456     lsass.exe       0x1e0427b8      6       566     0       False   2013-01-12 16:38:16.000000 UTC  N/A     Disabled
764     560     svchost.exe     0x1e1b5c20      7       263     0       False   2013-01-12 16:38:23.000000 UTC  N/A     Disabled
404     396     csrss.exe       0x1e49fd40      9       469     0       False   2013-01-12 16:38:14.000000 UTC  N/A     Disabled
456     396     wininit.exe     0x1e4ac2b8      3       77      0       False   2013-01-12 16:38:14.000000 UTC  N/A     Disabled
500     448     winlogon.exe    0x1e4ced40      3       111     1       False   2013-01-12 16:38:14.000000 UTC  N/A     Disabled
308     4       smss.exe        0x1ea3ed40      2       29      N/A     False   2013-01-12 16:38:09.000000 UTC  N/A     Disabled
1872    560     sppsvc.exe      0x1eaded40      4       143     0       False   2013-01-12 16:39:02.000000 UTC  N/A     Disabled
468     448     csrss.exe       0x1eb03a00      10      471     1       False   2013-01-12 16:38:14.000000 UTC  N/A     Disabled
1616    2772    cmd.exe 0x1f6aa030      2       101     1       False   2013-01-12 16:55:49.000000 UTC  N/A     Disabled
904     560     svchost.exe     0x1f887918      17      409     0       False   2013-01-12 16:38:24.000000 UTC  N/A     Disabled
3228    468     conhost.exe     0x1fa595b0      2       54      1       False   2013-01-12 16:44:50.000000 UTC  N/A     Disabled
3452    2548    swriter.exe     0x1fa6a2a0      1       19      1       False   2013-01-12 16:41:01.000000 UTC  N/A     Disabled
1720    832     audiodg.exe     0x1fa90d40      5       117     0       False   2013-01-12 16:58:11.000000 UTC  N/A     Disabled
3144    3152    winpmem-1.3.1.  0x1fabfd40      1       23      1       False   2013-01-12 16:59:17.000000 UTC  N/A     Disabled
3044    1136    iexplore.exe    0x1fb4d338      37      937     1       False   2013-01-12 16:57:46.000000 UTC  N/A     Disabled
2600    468     conhost.exe     0x1fc9c288      1       35      1       False   2013-01-12 16:40:28.000000 UTC  N/A     Disabled
2676    2548    VMwareUser.exe  0x1fca9220      8       190     1       False   2013-01-12 16:40:30.000000 UTC  N/A     Disabled
2352    560     taskhost.exe    0x1fcc0620      8       149     1       False   2013-01-12 16:40:24.000000 UTC  N/A     Disabled
2548    2484    explorer.exe    0x1fcc6030      24      766     1       False   2013-01-12 16:40:27.000000 UTC  N/A     Disabled
2496    904     dwm.exe 0x1fcd44d0      5       77      1       False   2013-01-12 16:40:25.000000 UTC  N/A     Disabled
2568    1612    TPAutoConnect.  0x1fce2880      5       146     1       False   2013-01-12 16:40:28.000000 UTC  N/A     Disabled
2772    2548    iexplore.exe    0x1fd6b030      2       74      1       False   2013-01-12 16:40:34.000000 UTC  N/A     Disabled
2720    2548    AvastUI.exe     0x1fd784b0      14      220     1       False   2013-01-12 16:40:31.000000 UTC  N/A     Disabled
2660    2548    VMwareTray.exe  0x1fd82438      5       80      1       False   2013-01-12 16:40:29.000000 UTC  N/A     Disabled
3564    3512    soffice.bin     0x1fd8ca58      12      400     1       False   2013-01-12 16:41:05.000000 UTC  N/A     Disabled
3512    3452    soffice.exe     0x1fda4030      1       28      1       False   2013-01-12 16:41:03.000000 UTC  N/A     Disabled
3176    560     wmpnetwk.exe    0x1fdd35b8      9       240     0       False   2013-01-12 16:40:48.000000 UTC  N/A     Disabled
3152    2548    cmd.exe 0x1fdf7030      1       23      1       False   2013-01-12 16:44:50.000000 UTC  N/A     Disabled
4       0       System  0x1ffb8b78      103     3257    N/A     False   2013-01-12 16:38:09.000000 UTC  N/A     Disabled
```

However, upon looking at the pstree output:

```bash
$ cat pstree.txt
Volatility 3 Framework 2.28.0

PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        Audit   Cmd     Path

4       0       System  0x87978b78      103     3257    N/A     False   2013-01-12 16:38:09.000000 UTC  N/A     -       -       -
* 308   4       smss.exe        0x88c3ed40      2       29      N/A     False   2013-01-12 16:38:09.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\smss.exe \SystemRoot\System32\smss.exe    \SystemRoot\System32\smss.exe
404     396     csrss.exe       0x8929fd40      9       469     0       False   2013-01-12 16:38:14.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\csrss.exe%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16  C:\Windows\system32\csrss.exe
456     396     wininit.exe     0x892ac2b8      3       77      0       False   2013-01-12 16:38:14.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\wininit.exe       -       -
* 560   456     services.exe    0x896294c0      6       205     0       False   2013-01-12 16:38:16.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\services.exe      C:\Windows\system32\services.exe        C:\Windows\system32\services.exe
** 904  560     svchost.exe     0x89852918      17      409     0       False   2013-01-12 16:38:24.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe       C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted C:\Windows\System32\svchost.exe
*** 2496        904     dwm.exe 0x87ad44d0      5       77      1       False   2013-01-12 16:40:25.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\dwm.exe  "C:\Windows\system32\Dwm.exe"    C:\Windows\system32\Dwm.exe
** 1172 560     svchost.exe     0x898b2790      15      475     0       False   2013-01-12 16:38:27.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe       C:\Windows\system32\svchost.exe -k NetworkService       C:\Windows\system32\svchost.exe
** 3352 560     svchost.exe     0x89f3d2c0      9       141     0       False   2013-01-12 16:40:58.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe       C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation       C:\Windows\system32\svchost.exe
** 928  560     svchost.exe     0x8986b030      26      869     0       False   2013-01-12 16:38:24.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe       C:\Windows\system32\svchost.exe -k netsvcs      C:\Windows\system32\svchost.exe
** 3624 560     svchost.exe     0x89f1d3e8      14      348     0       False   2013-01-12 16:41:22.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe       C:\Windows\System32\svchost.exe -k secsvcs      C:\Windows\System32\svchost.exe
** 1712 560     spoolsv.exe     0x8a0f9c40      14      338     0       False   2013-01-12 16:38:58.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\spoolsv.exe       C:\Windows\System32\spoolsv.exe C:\Windows\System32\spoolsv.exe
** 1968 560     vmtoolsd.exe    0x8a1d84e0      6       220     0       False   2013-01-12 16:39:14.000000 UTC  N/A     \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\vmtoolsd.exe     "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"     C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
** 2352 560     taskhost.exe    0x87ac0620      8       149     1       False   2013-01-12 16:40:24.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\taskhost.exe      "taskhost.exe"  C:\Windows\system32\taskhost.exe
** 692  560     svchost.exe     0x8962f030      10      353     0       False   2013-01-12 16:38:21.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe       C:\Windows\system32\svchost.exe -k DcomLaunch   C:\Windows\system32\svchost.exe
** 1084 560     svchost.exe     0x898911a8      10      257     0       False   2013-01-12 16:38:26.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe       C:\Windows\system32\svchost.exe -k LocalService C:\Windows\system32\svchost.exe
** 448  560     VMUpgradeHelpe  0x8a1f5030      4       89      0       False   2013-01-12 16:39:21.000000 UTC  N/A     \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\VMUpgradeHelper.exe      -       -
*** 468 448     csrss.exe       0x88d03a00      10      471     1       False   2013-01-12 16:38:14.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\csrss.exe%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16  C:\Windows\system32\csrss.exe
**** 2600       468     conhost.exe     0x87a9c288      1       35      1       False   2013-01-12 16:40:28.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\conhost.exe       -       -
**** 3228       468     conhost.exe     0x87c595b0      2       54      1       False   2013-01-12 16:44:50.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\conhost.exe       -       -
**** 2168       468     conhost.exe     0x954826b0      2       49      1       False   2013-01-12 16:55:50.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\conhost.exe       \??\C:\Windows\system32\conhost.exe     C:\Windows\system32\conhost.exe
*** 500 448     winlogon.exe    0x892ced40      3       111     1       False   2013-01-12 16:38:14.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\winlogon.exe      -       -
** 832  560     svchost.exe     0x89805420      19      435     0       False   2013-01-12 16:38:23.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe       C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted        C:\Windows\System32\svchost.exe
*** 1720        832     audiodg.exe     0x87c90d40      5       117     0       False   2013-01-12 16:58:11.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\audiodg.exe       C:\Windows\system32\AUDIODG.EXE 0x298   C:\Windows\system32\AUDIODG.EXE
** 1220 560     AvastSvc.exe    0x898a7868      66      1180    0       False   2013-01-12 16:38:28.000000 UTC  N/A     \Device\HarddiskVolume1\Program Files\AVAST Software\Avast\AvastSvc.exe    "C:\Program Files\AVAST Software\Avast\AvastSvc.exe"    C:\Program Files\AVAST Software\Avast\AvastSvc.exe
** 1612 560     TPAutoConnSvc.  0x9542a030      9       135     0       False   2013-01-12 16:39:23.000000 UTC  N/A     \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\TPAutoConnSvc.exe        "C:\Program Files\VMware\VMware Tools\TPAutoConnSvc.exe"        C:\Program Files\VMware\VMware Tools\TPAutoConnSvc.exe
*** 2568        1612    TPAutoConnect.  0x87ae2880      5       146     1       False   2013-01-12 16:40:28.000000 UTC  N/A     \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\TPAutoConnect.exe        TPAutoConnect.exe -q -i vmware -a COM1 -F 30    C:\Program Files\VMware\VMware Tools\TPAutoConnect.exe
** 1872 560     sppsvc.exe      0x88cded40      4       143     0       False   2013-01-12 16:39:02.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\sppsvc.exe-       -
** 336  560     wlms.exe        0x9541c7e0      4       45      0       False   2013-01-12 16:39:21.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\wlms\wlms.exe     -       -
** 1748 560     svchost.exe     0x8a102748      18      310     0       False   2013-01-12 16:38:58.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe       C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork        C:\Windows\system32\svchost.exe
** 2900 560     SearchIndexer.  0x898fbb18      13      636     0       False   2013-01-12 16:40:38.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\SearchIndexer.exe C:\Windows\system32\SearchIndexer.exe /Embedding        C:\Windows\system32\SearchIndexer.exe
** 3176 560     wmpnetwk.exe    0x87bd35b8      9       240     0       False   2013-01-12 16:40:48.000000 UTC  N/A     \Device\HarddiskVolume1\Program Files\Windows Media Player\wmpnetwk.exe    "C:\Program Files\Windows Media Player\wmpnetwk.exe"    C:\Program Files\Windows Media Player\wmpnetwk.exe
** 764  560     svchost.exe     0x897b5c20      7       263     0       False   2013-01-12 16:38:23.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\svchost.exe       C:\Windows\system32\svchost.exe -k RPCSS        C:\Windows\system32\svchost.exe
* 584   456     lsm.exe 0x8962f7e8      10      142     0       False   2013-01-12 16:38:16.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\lsm.exe        C:\Windows\system32\lsm.exe        C:\Windows\system32\lsm.exe
* 576   456     lsass.exe       0x896427b8      6       566     0       False   2013-01-12 16:38:16.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\lsass.exeC:\Windows\system32\lsass.exe    C:\Windows\system32\lsass.exe
2548    2484    explorer.exe    0x87ac6030      24      766     1       False   2013-01-12 16:40:27.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\explorer.exe    C:\Windows\Explorer.EXE    C:\Windows\Explorer.EXE
* 2720  2548    AvastUI.exe     0x87b784b0      14      220     1       False   2013-01-12 16:40:31.000000 UTC  N/A     \Device\HarddiskVolume1\Program Files\AVAST Software\Avast\AvastUI.exe     "C:\Program Files\AVAST Software\Avast\AvastUI.exe" /nogui      C:\Program Files\AVAST Software\Avast\AvastUI.exe
* 2660  2548    VMwareTray.exe  0x87b82438      5       80      1       False   2013-01-12 16:40:29.000000 UTC  N/A     \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\VMwareTray.exe   "C:\Program Files\VMware\VMware Tools\VMwareTray.exe"   C:\Program Files\VMware\VMware Tools\VMwareTray.exe
* 1232  2548    taskmgr.exe     0x95495c18      6       116     1       False   2013-01-12 16:42:29.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\taskmgr.exe       "C:\Windows\system32\taskmgr.exe" /4    C:\Windows\system32\taskmgr.exe
* 3152  2548    cmd.exe 0x87bf7030      1       23      1       False   2013-01-12 16:44:50.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\cmd.exe        "C:\Windows\system32\cmd.exe"      C:\Windows\system32\cmd.exe
** 3144 3152    winpmem-1.3.1.  0x87cbfd40      1       23      1       False   2013-01-12 16:59:17.000000 UTC  N/A     \Device\HarddiskVolume1\Users\JOHNDO~1\AppData\Local\Temp\imagedump\winpmem-1.3.1.exe      winpmem-1.3.1.exe  ram.dmp      C:\Users\JOHNDO~1\AppData\Local\Temp\imagedump\winpmem-1.3.1.exe
* 1136  2548    iexplore.exe    0x9549f678      18      454     1       False   2013-01-12 16:57:44.000000 UTC  N/A     \Device\HarddiskVolume1\Program Files\Internet Explorer\iexplore.exe       "C:\Program Files\Internet Explorer\iexplore.exe"       C:\Program Files\Internet Explorer\iexplore.exe
** 3044 1136    iexplore.exe    0x87d4d338      37      937     1       False   2013-01-12 16:57:46.000000 UTC  N/A     \Device\HarddiskVolume1\Program Files\Internet Explorer\iexplore.exe       "C:\Program Files\Internet Explorer\iexplore.exe" SCODEF:1136 CREDAT:71937      C:\Program Files\Internet Explorer\iexplore.exe
* 2676  2548    VMwareUser.exe  0x87aa9220      8       190     1       False   2013-01-12 16:40:30.000000 UTC  N/A     \Device\HarddiskVolume1\Program Files\VMware\VMware Tools\VMwareUser.exe   "C:\Program Files\VMware\VMware Tools\VMwareUser.exe"   C:\Program Files\VMware\VMware Tools\VMwareUser.exe
* 2772  2548    iexplore.exe    0x87b6b030      2       74      1       False   2013-01-12 16:40:34.000000 UTC  N/A     \Device\HarddiskVolume1\Users\John Doe\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe       "C:\Users\John Doe\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe"       C:\Users\John Doe\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe
** 1616 2772    cmd.exe 0x89898030      2       101     1       False   2013-01-12 16:55:49.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\cmd.exe        cmd.exe    C:\Windows\system32\cmd.exe
* 2744  2548    StikyNot.exe    0x898fe8c0      8       135     1       False   2013-01-12 16:40:32.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\StikyNot.exe      "C:\Windows\System32\StikyNot.exe"      C:\Windows\System32\StikyNot.exe
* 3452  2548    swriter.exe     0x87c6a2a0      1       19      1       False   2013-01-12 16:41:01.000000 UTC  N/A     \Device\HarddiskVolume1\Program Files\LibreOffice 3.6\program\swriter.exe  -       -
** 3512 3452    soffice.exe     0x87ba4030      1       28      1       False   2013-01-12 16:41:03.000000 UTC  N/A     \Device\HarddiskVolume1\Program Files\LibreOffice 3.6\program\soffice.exe  -       -
*** 3564        3512    soffice.bin     0x87b8ca58      12      400     1       False   2013-01-12 16:41:05.000000 UTC  N/A     \Device\HarddiskVolume1\Program Files\LibreOffice 3.6\program\soffice.bin  "C:\Program Files\LibreOffice 3.6\program\swriter.exe" "-o" "C:\Users\John Doe\Documents\Procedure Winpmemdump.odt" "--writer" "-env:OOO_CWD=2C:\\Users\\John Doe\\Documents"      C:\Program Files\LibreOffice 3.6\program\soffice.bin
3556    3544    soffice.bin     0x95483d18      0       -       1       False   2013-01-12 16:41:05.000000 UTC  2013-01-12 16:41:39.000000 UTC  \Device\HarddiskVolume1\Program Files\LibreOffice 3.6\program\soffice.bin  -       -
```

Something stood out to me like a wolf, specfically:

```bash
* 2772  2548    iexplore.exe    0x87b6b030      2       74      1       False   2013-01-12 16:40:34.000000 UTC  N/A     \Device\HarddiskVolume1\Users\John Doe\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe       "C:\Users\John Doe\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe"       C:\Users\John Doe\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe
** 1616 2772    cmd.exe 0x89898030      2       101     1       False   2013-01-12 16:55:49.000000 UTC  N/A     \Device\HarddiskVolume1\Windows\System32\cmd.exe        cmd.exe    C:\Windows\system32\cmd.exe
```

Two huge red flags here:
1. Internet explorer executable in quick launch, which should only contain lnk shortcuts
2. This iexplore.exe is a parent to a cmd.exe process

To state the obvious, internet explorer does NOT run commands (if anything at all) and definitely does not spawn child cmd.exe processes, so this is most probably our suspicious file.

Full path: `C:\Users\John Doe\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe`

So our flag must be the md5sum of this path string (-n to tell echo to not add a \n char):
```bash
$ echo -n "C:\Users\John Doe\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\iexplore.exe" | md5sum
49979149632639432397b3a1df8cb43d  
```

And that's our flag!

# FLAG
49979149632639432397b3a1df8cb43d
