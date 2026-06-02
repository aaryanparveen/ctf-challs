# 2 / 3 Did you see my desktop?

## Challenge Details

- Category: Forensics
- Points: 3
- Validation: 947
- Author: PRL
- Status: Done
# Handout
`Part 2 of 3 Using the file b64021d477b2505fcb37e6b46701bb5a.zip 2 / 3 Did you see my desktop?`
https://ringzer0ctf.com/files/b64021d477b2505fcb37e6b46701bb5a.zip

## Walkthrough

This prompt is fairly straightforward, the flag is probably a file on the desktop, let's use the filescan plugin and grep for desktop.
```bash
$ vol -f 5bd2510a83e82d271b7bf7fa4e0970d1  windows.filescan |  grep Desktop -i
0x3f01f80  100.0\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Remote Desktop Connection.lnk
0x3f02f10       \ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Windows PowerShell\desktop.ini
0x3f0d840       \Users\Public\Desktop\desktop.ini
0x3f0de00       \Users\Public\Documents\desktop.ini
0x3f0df80       \Users\Public\desktop.ini
0x3f5cad0       \Users\Public\Videos\desktop.ini
0x3f65748       \Users\flag\AppData\Roaming\Microsoft\Windows\Libraries\desktop.ini
0x3f65aa8       \Users\flag\Links\desktop.ini
0x3f66308       \ProgramData\Microsoft\Windows\Start Menu\Programs\Games\desktop.ini
0x3f667f8       \ProgramData\Microsoft\Windows\Start Menu\Programs\desktop.ini
0x3f68ba8       \ProgramData\Microsoft\Windows\Start Menu\desktop.ini
0x3f7e458       \Users\flag\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\desktop.ini
0x3f918b0       \ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Tablet PC\Desktop.ini
0x3fb67b0       \Users\flag\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\desktop.ini
0x3fe43b8       \Users\flag\Downloads\desktop.ini
0x3fe5038       \ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini
0x3fe5a00       \ProgramData\Microsoft\Windows\Start Menu\Programs\Maintenance\Desktop.ini
0x3fe7038       \Users\flag\Contacts\desktop.ini
0xdc51df8       \Users\desktop.ini
0xdc919d8       \Users\flag\Favorites\desktop.ini
0xdde3258       \Users\Public\Desktop
0xdde4f80       \Users\Public\Desktop
0xde13378       \ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Accessibility\Desktop.ini
0xe401450       \Users\flag\Desktop
0xe4a8598       \Users\flag\Desktop
0xe4c9948       \ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\System Tools\Desktop.ini
0xe4dae10       \Users\flag\Searches\desktop.ini
0xe4f5758       \$Recycle.Bin\S-1-5-21-2338092958-3425525054-89474938-1000\desktop.ini
0xeb8fe58       \Users\flag\Documents\desktop.ini
0xeb9fb20       \Users\flag\Desktop
0xebaad00       \Users\flag\Videos\desktop.ini
0xebb3500       \Users\flag\Desktop\desktop.ini
0xebb9038       \Users\flag\Saved Games\desktop.ini
0xeca0c68       \Users\flag\AppData\Roaming\Microsoft\Windows\SendTo\Desktop.ini
```
No flags here, maybe volatility failed to parse the files correctly, lets find an alternate approach: through processes:
```bash
$ vol -f 5bd2510a83e82d271b7bf7fa4e0970d1  windows.pslist
Volatility 3 Framework 2.28.0
Progress:  100.00               PDB scanning finished
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

4       0       System  0x83d92a00      79      495     N/A     False   2014-03-09 23:49:30.000000 UTC  N/A     Disabled
252     4       smss.exe        0x84444a88      2       29      N/A     False   2014-03-09 23:49:30.000000 UTC  N/A     Disabled
328     320     csrss.exe       0x84bacd40      8       375     0       False   2014-03-09 23:49:35.000000 UTC  N/A     Disabled
364     356     csrss.exe       0x84afb478      7       168     1       False   2014-03-09 23:49:36.000000 UTC  N/A     Disabled
372     320     wininit.exe     0x84b03530      3       76      0       False   2014-03-09 23:49:36.000000 UTC  N/A     Disabled
400     356     winlogon.exe    0x84b0f530      5       135     1       False   2014-03-09 23:49:36.000000 UTC  N/A     Disabled
460     372     services.exe    0x84bbfab8      10      188     0       False   2014-03-09 23:49:37.000000 UTC  N/A     Disabled
468     372     lsass.exe       0x84bcc588      7       545     0       False   2014-03-09 23:49:38.000000 UTC  N/A     Disabled
476     372     lsm.exe 0x84bce988      10      144     0       False   2014-03-09 23:49:38.000000 UTC  N/A     Disabled
572     460     svchost.exe     0x84bfd030      11      346     0       False   2014-03-09 23:49:41.000000 UTC  N/A     Disabled
628     460     VBoxService.ex  0x84c0c030      12      117     0       False   2014-03-09 23:49:41.000000 UTC  N/A     Disabled
692     460     svchost.exe     0x84c15c18      8       250     0       False   2014-03-09 20:49:43.000000 UTC  N/A     Disabled
780     460     svchost.exe     0x84c37b38      21      461     0       False   2014-03-09 20:49:44.000000 UTC  N/A     Disabled
816     460     svchost.exe     0x84c43b78      19      418     0       False   2014-03-09 20:49:44.000000 UTC  N/A     Disabled
844     460     svchost.exe     0x84c71030      35      947     0       False   2014-03-09 20:49:44.000000 UTC  N/A     Disabled
1008    460     svchost.exe     0x84c908e8      14      320     0       False   2014-03-09 20:49:46.000000 UTC  N/A     Disabled
1096    460     svchost.exe     0x84ca3658      15      370     0       False   2014-03-09 20:49:47.000000 UTC  N/A     Disabled
1272    460     spoolsv.exe     0x843ed030      12      284     0       False   2014-03-09 20:49:50.000000 UTC  N/A     Disabled
1316    460     svchost.exe     0x843a5d40      18      312     0       False   2014-03-09 20:49:51.000000 UTC  N/A     Disabled
1416    460     svchost.exe     0x84af4bf0      12      213     0       False   2014-03-09 20:49:52.000000 UTC  N/A     Disabled
1972    460     taskhost.exe    0x84d86030      8       165     1       False   2014-03-09 20:50:01.000000 UTC  N/A     Disabled
216     816     dwm.exe 0x84d94d40      3       69      1       False   2014-03-09 20:50:02.000000 UTC  N/A     Disabled
284     2040    explorer.exe    0x84d96d40      30      900     1       False   2014-03-09 20:50:03.000000 UTC  N/A     Disabled
1336    284     VBoxTray.exe    0x84d79aa0      10      397     1       False   2014-03-09 20:50:06.000000 UTC  N/A     Disabled
1920    460     SearchIndexer.  0x8439f030      14      663     0       False   2014-03-09 20:50:12.000000 UTC  N/A     Disabled
472     1920    SearchProtocol  0x84e0fb28      9       379     0       False   2014-03-09 20:50:15.000000 UTC  N/A     Disabled
1684    460     sppsvc.exe      0x84c359f0      7       154     0       False   2014-03-09 20:51:57.000000 UTC  N/A     Disabled
1644    460     svchost.exe     0x843add40      11      301     0       False   2014-03-09 20:51:58.000000 UTC  N/A     Disabled
2380    572     WmiPrvSE.exe    0x83eff030      6       110     0       False   2014-03-09 20:53:55.000000 UTC  N/A     Disabled
2528    284     notepad.exe     0x844d9750      1       61      1       False   2014-03-09 20:54:39.000000 UTC  N/A     Disabled
2744    1920    SearchFilterHo  0x83f40720      7       141     0       False   2014-03-09 20:55:56.000000 UTC  N/A     Disabled
3148    780     audiodg.exe     0x83f74d40      6       125     0       False   2014-03-09 20:57:23.000000 UTC  N/A     Disabled
3488    284     DumpIt.exe      0x83f84d40      2       37      1       False   2014-03-09 20:57:46.000000 UTC  N/A     Disabled
3500    364     conhost.exe     0x83eb6030      2       51      1       False   2014-03-09 20:57:47.000000 UTC  N/A     Disabled

```
Nothing too suspicious here except that notepad is running, so we might have something interesting there, DumpIt.exe is the software used for generating the memory dump, let's also confirm that no processes have children processes which they shouldn't using pstree.
```bash
$ vol -f 5bd2510a83e82d271b7bf7fa4e0970d1  windows.pstree
Volatility 3 Framework 2.28.0
Progress:  100.00               PDB scanning finished
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        Audit   Cmd  Path

4       0       System  0x83d92a00      79      495     N/A     False   2014-03-09 23:49:30.000000 UTC  N/A     -       -       -
* 252   4       smss.exe        0x84444a88      2       29      N/A     False   2014-03-09 23:49:30.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\smss.exe     \SystemRoot\System32\smss.exe   \SystemRoot\System32\smss.exe
328     320     csrss.exe       0x84bacd40      8       375     0       False   2014-03-09 23:49:35.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\csrss.exe    %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16  C:\Windows\system32\csrss.exe
364     356     csrss.exe       0x84afb478      7       168     1       False   2014-03-09 23:49:36.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\csrss.exe    %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,12288,512 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16  C:\Windows\system32\csrss.exe
* 3500  364     conhost.exe     0x83eb6030      2       51      1       False   2014-03-09 20:57:47.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\conhost.exe  \??\C:\Windows\system32\conhost.exe     C:\Windows\system32\conhost.exe
372     320     wininit.exe     0x84b03530      3       76      0       False   2014-03-09 23:49:36.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\wininit.exe  wininit.exe     C:\Windows\system32\wininit.exe
* 476   372     lsm.exe 0x84bce988      10      144     0       False   2014-03-09 23:49:38.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\lsm.exe      C:\Windows\system32\lsm.exe     C:\Windows\system32\lsm.exe
* 468   372     lsass.exe       0x84bcc588      7       545     0       False   2014-03-09 23:49:38.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\lsass.exe    C:\Windows\system32\lsass.exe   C:\Windows\system32\lsass.exe
* 460   372     services.exe    0x84bbfab8      10      188     0       False   2014-03-09 23:49:37.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\services.exe C:\Windows\system32\services.exe        C:\Windows\system32\services.exe
** 1920 460     SearchIndexer.  0x8439f030      14      663     0       False   2014-03-09 20:50:12.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\SearchIndexer.exe    C:\Windows\system32\SearchIndexer.exe /Embedding        C:\Windows\system32\SearchIndexer.exe
*** 472 1920    SearchProtocol  0x84e0fb28      9       379     0       False   2014-03-09 20:50:15.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\SearchProtocolHost.exe       "C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe1_ Global\UsGthrCtrlFltPipeMssGthrPipe1 1 -2147483646 "Software\Microsoft\Windows Search" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" "C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc" "DownLevelDaemon"         C:\Windows\system32\SearchProtocolHost.exe
*** 2744        1920    SearchFilterHo  0x83f40720      7       141     0       False   2014-03-09 20:55:56.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\SearchFilterHost.exe "C:\Windows\system32\SearchFilterHost.exe" 0 504 508 516 65536 512      C:\Windows\system32\SearchFilterHost.exe
** 1316 460     svchost.exe     0x843a5d40      18      312     0       False   2014-03-09 20:49:51.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\svchost.exe  C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork        C:\Windows\system32\svchost.exe
** 1096 460     svchost.exe     0x84ca3658      15      370     0       False   2014-03-09 20:49:47.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\svchost.exe  C:\Windows\system32\svchost.exe -k NetworkService       C:\Windows\system32\svchost.exe
** 1416 460     svchost.exe     0x84af4bf0      12      213     0       False   2014-03-09 20:49:52.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\svchost.exe  C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation       C:\Windows\system32\svchost.exe
** 780  460     svchost.exe     0x84c37b38      21      461     0       False   2014-03-09 20:49:44.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\svchost.exe  C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted        C:\Windows\System32\svchost.exe
*** 3148        780     audiodg.exe     0x83f74d40      6       125     0       False   2014-03-09 20:57:23.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\audiodg.exe  C:\Windows\system32\AUDIODG.EXE 0x644   C:\Windows\system32\AUDIODG.EXE
** 844  460     svchost.exe     0x84c71030      35      947     0       False   2014-03-09 20:49:44.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\svchost.exe  C:\Windows\system32\svchost.exe -k netsvcs      C:\Windows\system32\svchost.exe
** 1644 460     svchost.exe     0x843add40      11      301     0       False   2014-03-09 20:51:58.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\svchost.exe  C:\Windows\System32\svchost.exe -k secsvcs      C:\Windows\System32\svchost.exe
** 816  460     svchost.exe     0x84c43b78      19      418     0       False   2014-03-09 20:49:44.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\svchost.exe  C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted C:\Windows\System32\svchost.exe
*** 216 816     dwm.exe 0x84d94d40      3       69      1       False   2014-03-09 20:50:02.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\dwm.exe      "C:\Windows\system32\Dwm.exe"   C:\Windows\system32\Dwm.exe
** 1008 460     svchost.exe     0x84c908e8      14      320     0       False   2014-03-09 20:49:46.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\svchost.exe  C:\Windows\system32\svchost.exe -k LocalService C:\Windows\system32\svchost.exe
** 628  460     VBoxService.ex  0x84c0c030      12      117     0       False   2014-03-09 23:49:41.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\VBoxService.exe      system32\VBoxService.exe        C:\Windows\system32\VBoxService.exe
** 692  460     svchost.exe     0x84c15c18      8       250     0       False   2014-03-09 20:49:43.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\svchost.exe  C:\Windows\system32\svchost.exe -k RPCSS        C:\Windows\system32\svchost.exe
** 1972 460     taskhost.exe    0x84d86030      8       165     1       False   2014-03-09 20:50:01.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\taskhost.exe "taskhost.exe"  C:\Windows\system32\taskhost.exe
** 1684 460     sppsvc.exe      0x84c359f0      7       154     0       False   2014-03-09 20:51:57.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\sppsvc.exe   C:\Windows\system32\sppsvc.exe  C:\Windows\system32\sppsvc.exe
** 1272 460     spoolsv.exe     0x843ed030      12      284     0       False   2014-03-09 20:49:50.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\spoolsv.exe  C:\Windows\System32\spoolsv.exe C:\Windows\System32\spoolsv.exe
** 572  460     svchost.exe     0x84bfd030      11      346     0       False   2014-03-09 23:49:41.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\svchost.exe  C:\Windows\system32\svchost.exe -k DcomLaunch   C:\Windows\system32\svchost.exe
*** 2380        572     WmiPrvSE.exe    0x83eff030      6       110     0       False   2014-03-09 20:53:55.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\wbem\WmiPrvSE.exe    C:\Windows\system32\wbem\wmiprvse.exe   C:\Windows\system32\wbem\wmiprvse.exe
400     356     winlogon.exe    0x84b0f530      5       135     1       False   2014-03-09 23:49:36.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\winlogon.exe winlogon.exe    C:\Windows\system32\winlogon.exe
284     2040    explorer.exe    0x84d96d40      30      900     1       False   2014-03-09 20:50:03.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\explorer.exe  C:\Windows\Explorer.EXE C:\Windows\Explorer.EXE
* 1336  284     VBoxTray.exe    0x84d79aa0      10      397     1       False   2014-03-09 20:50:06.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\VBoxTray.exe "C:\Windows\System32\VBoxTray.exe"      C:\Windows\System32\VBoxTray.exe
* 2528  284     notepad.exe     0x844d9750      1       61      1       False   2014-03-09 20:54:39.000000 UTC  N/A     \Device\HarddiskVolume2\Windows\System32\notepad.exe  "C:\Windows\system32\NOTEPAD.EXE" C:\Users\flag\Desktop\F$L%A^G-5bd2510a83e82d271b7bf7fa4e0970d1.txt  C:\Windows\system32\NOTEPAD.EXE
* 3488  284     DumpIt.exe      0x83f84d40      2       37      1       False   2014-03-09 20:57:46.000000 UTC  N/A     \Device\HarddiskVolume2\Users\flag\Downloads\DumpIt\DumpIt.exe        "C:\Users\flag\Downloads\DumpIt\DumpIt.exe"     C:\Users\flag\Downloads\DumpIt\DumpIt.exe
```
I guess we won't have to look at the notepad contents just yet,
`"C:\Windows\system32\NOTEPAD.EXE" C:\Users\flag\Desktop\F$L%A^G-5bd2510a83e82d271b7bf7fa4e0970d1.txt`
There's our second flag!
# FLAG
FLAG-5bd2510a83e82d271b7bf7fa4e0970d1