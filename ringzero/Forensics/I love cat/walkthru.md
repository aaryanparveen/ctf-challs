# I love cat

## Challenge Details

- Category: Forensics
- Points: 2
- Validation: 1010
- Author: Mr.Un1k0d3r
- Status: Done
# Handout
`I love cat! Do you? User: cat Password: cat`
ssh://challenges.ringzer0ctf.com:10252

## Walkthrough
Who in their right mind would hate cats????
Let' SSH, initial guess: restricted shell with cat access!
```bash
─$ ssh cat@challenges.ringzer0ctf.com -p 10252
cat@challenges.ringzer0ctf.com's password:

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law
```

Let's look around.

```bash
cat@forensics-252-i-love-cat:~$ ls -a
.  ..  .bash_profile  .bashrc  commands  flag.txt
cat@forensics-252-i-love-cat:~$ cat flag.txt
**************************** WHERE IS THE FLAG ? ****************************
```
Of course if it was that easy I'd be wasting my time. Although, I've seen this before. Very often some ctf challenges will have non printable characters which can't be directly displayed by cat, but can be printed using `-v`, which instructs cat to reveal hidden/control non-printing characters in a visible form. Could it be?
```bash
cat@forensics-252-i-love-cat:~$ cat -v flag.txt
FLAG-0K14eDrm4t5g7KD54X8Dl3NNcZ956oCK^M**************************** WHERE IS THE FLAG ? ****************************
```
and there it is! ^M means carriage return :nerd:

# FLAG
FLAG-0K14eDrm4t5g7KD54X8Dl3NNcZ956oCK