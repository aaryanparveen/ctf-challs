# 3 / 3 Suspicious account password?

## Challenge Details

- Category: Forensics
- Points: 4
- Validation: 771
- Author: PRL
- Status: Done
# Handout
`Part 3 of 3 Using the file b64021d477b2505fcb37e6b46701bb5a.zip 3 / 3 Suspicious account password?`
https://ringzer0ctf.com/files/b64021d477b2505fcb37e6b46701bb5a.zip

## Walkthrough
Seems straightforward enough, we need to crack the account password. We could go about doing this in various ways:
- mimikatz
- dump lsass.exe
- use hashdump
I like to use hashdump, in volatility2 you had to find the offsets for the SYSTEM and SAM hives using hivelist and use that with hashdump, but vol3 is a lot simpler it does that for you. Using the hashdump plugin:
```bash
$ vol -f 5bd2510a83e82d271b7bf7fa4e0970d1  windows.hashdump
Volatility 3 Framework 2.28.0

Administrator   500     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
Guest   501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
flag    1000    aad3b435b51404eeaad3b435b51404ee        3008c87294511142799dca1191e69a0f
```
These are NTLM hashes. We can crack each of them using hashcat with the rockyou wordlist for now. If they fail we might have to use a ruleset (OneRuleToRuleThemAll) or a bigger wordlist.
Storing them to hashes.txt:
```bash
cat hashes.txt
31d6cfe0d16ae931b73c59d7e0c089c0
3008c87294511142799dca1191e69a0f
```
Hashcat mode 1000 is for NTLM.
```bash
hashcat -m 1000 hashes.txt 
Host memory required for this attack: 426 MB

Dictionary cache hit:
* Filename..: /home/hyp3rnov4/wordlists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

31d6cfe0d16ae931b73c59d7e0c089c0:
3008c87294511142799dca1191e69a0f:admin123

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: hashes.txt
Time.Started.....: Fri May 29 22:38:52 2026 (0 secs)
Time.Estimated...: Fri May 29 22:38:52 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/hyp3rnov4/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  5677.6 kH/s (10.45ms) @ Accel:256 Loops:1 Thr:32 Vec:1
Speed.#2.........:  4794.5 kH/s (0.21ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Speed.#*.........: 10472.0 kH/s
Recovered........: 2/2 (100.00%) Digests (total), 2/2 (100.00%) Digests (new)
Progress.........: 380928/14344384 (2.66%)
Rejected.........: 0/380928 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: vivien -> Boomer1
Candidates.#2....: Allen1 -> zelada
Hardware.Mon.#1..: Temp: 42c Util: 98% Core:2370MHz Mem:8150MHz Bus:8
Hardware.Mon.#2..: N/A

Started: Fri May 29 22:38:36 2026
Stopped: Fri May 29 22:38:53 2026
```
And there's our flag!

# FLAG
admin123