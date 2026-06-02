# Who I am?

## Challenge Details

- Category: Forensics
- Points: 2
- Validation: 1408
- Author: Mr.Un1k0d3r
- Status: Done

# Handout
`I'm looking for information about me! The website...`

## Walkthrough

Seems simple enough, information about me combined with the challenge name, let's presume it's talking about the website itself and not the ctf team, main things of interest could be:
dns records
whois records
keybase
pgp key

1. checking dns txt records:
```bash
$ dig TXT ringzer0ctf.com

; <<>> DiG 9.19.21-1-Debian <<>> TXT ringzer0ctf.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5345
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;ringzer0ctf.com.               IN      TXT

;; ANSWER SECTION:
ringzer0ctf.com.        900     IN      TXT     "FLAG-305l9RR202HG695t6Y8ZU77xyq"
ringzer0ctf.com.        900     IN      TXT     "google-site-verification=2VqXKiBrx_DOcV-E-4RgHYtCiCVGgZM42FKl_DlJqHk"
ringzer0ctf.com.        900     IN      TXT     "v=spf1 include:_spf.google.com ~all"
ringzer0ctf.com.        900     IN      TXT     "1VR0DekIWV_hxeVmj3RDZMmg2TRnDin5ltO9AJM_u1s"

;; Query time: 1620 msec
;; SERVER: 10.255.255.254#53(10.255.255.254) (UDP)
;; WHEN: Fri May 29 20:02:38 IST 2026
;; MSG SIZE  rcvd: 273
```

and there's our flag right there!

# FLAG 
FLAG-305l9RR202HG695t6Y8ZU77xyq