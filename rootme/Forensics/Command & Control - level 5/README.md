# Command & Control - level 5

## Challenge Details

- Category: Forensics
- Points: 25
- Validation: 16399
- Author: Thanat0s
- Status: TODO
# Handout
`Command & Control - level 5: Memory analysis; Berthier, the malware seems to be manually maintened on the workstations. Therefore it’s likely that the hackers have found all of the computers’ passwords. Since ACME’s computer fleet seems to be up to date, it’s probably only due to password weakness. John, the system administrator doesn’t believe you. Prove him wrong! Find john password.`
https://static.root-me.org/forensic/ch2/ch2.tbz2
## Walkthrough
It's the same dump from level 2, so our volatility patch should continue working. This is easy enough, we need to crack the account password. We could go about doing this in various ways:
- mimikatz
- dump lsass.exe
- use hashdump
I like to use hashdump, in volatility2 you had to find the offsets for the SYSTEM and SAM hives using hivelist and use that with hashdump, but vol3 is a lot simpler it does that for you. Using the hashdump plugin:
```bash
$ vol -f ch2.dmp windows.hashdump
Volatility 3 Framework 2.28.0
User    rid     lmhash  nthash

Administrator   500     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
Guest   501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
John Doe        1000    aad3b435b51404eeaad3b435b51404ee        b9f917853e3dbf6e6831ecce60725930
```
These are NTLM hashes. We can crack the one for john using hashcat with the rockyou wordlist for now. If they fail we might have to use a ruleset (OneRuleToRuleThemAll) or a bigger wordlist.
Storing it to hashes.txt:

```bash
cat hash.txt
b9f917853e3dbf6e6831ecce60725930
```

Hashcat mode 1000 is for NTLM.

```bash
$ hashcat -m 1000 hash.txt --wordlist ~/wordlists/rockyou.txt -w 4
hashcat (v6.2.6-851-g6716447df) starting

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 426 MB

Dictionary cache hit:
* Filename..: /home/hyp3rnov4/wordlists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

b9f917853e3dbf6e6831ecce60725930:passw0rd

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: b9f917853e3dbf6e6831ecce60725930
Time.Started.....: Sat Jun 13 17:03:44 2026 (0 secs)
Time.Estimated...: Sat Jun 13 17:03:44 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/hyp3rnov4/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:        0 H/s (0.00ms) @ Accel:2048 Loops:1 Thr:32 Vec:1
Speed.#2.........:  1472.5 kH/s (0.21ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Speed.#*.........:  1472.5 kH/s
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10240/14344384 (0.07%)
Rejected.........: 0/10240 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-0 Iteration:0-1
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: [Copying]
Candidates.#2....: 123456 -> 11221122
Hardware.Mon.#1..: Temp: 47c Util: 13% Core:2370MHz Mem:7000MHz Bus:8
Hardware.Mon.#2..: N/A

Started: Sat Jun 13 17:03:42 2026
Stopped: Sat Jun 13 17:03:45 2026
```

And there it is! `b9f917853e3dbf6e6831ecce60725930:passw0rd`
How secure.
# FLAG
passw0rd
