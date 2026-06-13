# Docker layers

## Challenge Details

- Category: Forensics
- Points: 20
- Validation: 3857
- Author: mayfly
- Status: Done
# Handout
`Docker layers: Overlays; I lost the password I used to encrypt my secret flag file. Could you help me to recover it ?`
https://static.root-me.org/forensic/ch29/ch29.tar
## Walkthrough
Extracting:
```bash
$ tar -xf ch29.tar && ls 
1bbd61a572ad5f5e2ac0f073465d10dc1c94a71359b0adfd2c105be4c1cb2507
316bbb8c58be42c73eefeb8fc0fdc6abb99bf3d5686dd5145fc7bb2f32790229.tar
3309d6da2bd696689a815f55f18db3f173bc9b9a180e5616faf4927436cf199d.tar
4942a1abcbfa1c325b1d7ed93d3cf6020f555be706672308a4a4a6b6d631d2e7.tar
5bcc45940862d5b93517a60629b05c844df751c9187a293d982047f01615cb30
743c70a5f809c27d5c396f7ece611bc2d7c85186f9fdeb68f70986ec6e4d165f.tar
82ba49da0bd5d767f35d4ae9507d6c4552f74e10f29777a2a27c97778962476d
8d364403e7bf70d7f57e807803892edf7304760352a397983ecccb3e76ca39fa.tar
8f0d75885373613641edc42db2a0007684a0e5de14c6f854e365c61f292f3b4d
b324f85f8104bfebd1ed873e90437c0235d7a43f025a047d5695fe461da717c6.json
b58c5e8ccaba8886661ddd3b315989f5cf7839ea06bbe36547c6f49993b0d0aa.tar
ca7f60c6e2a66972abcc3147da47397d1c2edb80bddf0db8ef94770ed28c5e16
ch29.tar
db04fe239ab708e4ab56ea0e5c1047449b7ea9e04df9db5b1b95d00c6980ff3f
manifest.json
repositories
```

Judging by the challenge name (docker layers), and these contents (manifest.json contents, tar files) we are looking at a docker save tarball, let's look around a bit:
```json
$ jq . manifest.json
[
  {
    "Config": "b324f85f8104bfebd1ed873e90437c0235d7a43f025a047d5695fe461da717c6.json",
    "RepoTags": [
      "docker.io/rootme/docker_layer:latest"
    ],
    "Layers": [
      "4942a1abcbfa1c325b1d7ed93d3cf6020f555be706672308a4a4a6b6d631d2e7.tar",
      "b58c5e8ccaba8886661ddd3b315989f5cf7839ea06bbe36547c6f49993b0d0aa.tar",
      "743c70a5f809c27d5c396f7ece611bc2d7c85186f9fdeb68f70986ec6e4d165f.tar",
      "316bbb8c58be42c73eefeb8fc0fdc6abb99bf3d5686dd5145fc7bb2f32790229.tar",
      "3309d6da2bd696689a815f55f18db3f173bc9b9a180e5616faf4927436cf199d.tar",
      "8d364403e7bf70d7f57e807803892edf7304760352a397983ecccb3e76ca39fa.tar"
    ]
  }
]
```
`docker.io/rootme/docker_layer:latest` is the image tag (figures), and each tar file is a layer making up the image.  `b324f85f8104bfebd1ed873e90437c0235d7a43f025a047d5695fe461da717c6.json` is our config. Let's look at that:
```json
$ jq . b324f85f8104bfebd1ed873e90437c0235d7a43f025a047d5695fe461da717c6.json
{
  "architecture": "amd64",
  "config": {
    "Hostname": "",
    "Domainname": "",
    "User": "",
    "AttachStdin": false,
    "AttachStdout": false,
    "AttachStderr": false,
    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ],
    "Cmd": [
      "bash"
    ],
    "Image": "sha256:e2f4c9cf03836dc422745bcfa146e18442682c41edbb2dd93314d54266c4e34e",
    "Volumes": null,
    "WorkingDir": "",
    "Entrypoint": null,
    "OnBuild": null,
    "Labels": null
  },
  "container": "47b44e84bd40cb569f6d8090b95e6727cce691073dced864f0367e61f4dc28db",
  "container_config": {
    "Hostname": "",
    "Domainname": "",
    "User": "",
    "AttachStdin": false,
    "AttachStdout": false,
    "AttachStderr": false,
    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ],
    "Cmd": [
      "/bin/sh",
      "-c",
      "rm /pass.txt"
    ],
    "Image": "sha256:e2f4c9cf03836dc422745bcfa146e18442682c41edbb2dd93314d54266c4e34e",
    "Volumes": null,
    "WorkingDir": "",
    "Entrypoint": null,
    "OnBuild": null,
    "Labels": null
  },
  "created": "2021-10-20T20:37:11.144733916Z",
  "docker_version": "20.10.8",
  "history": [
    {
      "created": "2021-08-31T01:20:55.806655339Z",
      "created_by": "/bin/sh -c #(nop) ADD file:d2abf27fe2e8b0b5f4da68c018560c73e11c53098329246e3e6fe176698ef941 in / "
    },
    {
      "created": "2021-08-31T01:20:56.191693866Z",
      "created_by": "/bin/sh -c #(nop)  CMD [\"bash\"]",
      "empty_layer": true
    },
    {
      "created": "2021-09-09T13:14:19.479630434Z",
      "created_by": "/bin/sh -c apt update -y"
    },
    {
      "created": "2021-09-09T13:14:26.296501534Z",
      "created_by": "/bin/sh -c apt install -y curl openssl"
    },
    {
      "created": "2021-10-20T20:37:09.013582649Z",
      "created_by": "/bin/sh -c #(nop) COPY file:2ca89eb39686ffcc3d2d87bbc9293559252cff471f80c2ed5d024b214f9a6fa3 in / "
    },
    {
      "created": "2021-10-20T20:37:10.282265118Z",
      "created_by": "/bin/sh -c echo -n $(curl -s https://pastebin.com/raw/P9Nkw866) | openssl enc -aes-256-cbc -iter 10 -pass pass:$(cat /pass.txt) -out flag.enc"
    },
    {
      "created": "2021-10-20T20:37:11.144733916Z",
      "created_by": "/bin/sh -c rm /pass.txt"
    }
  ],
  "os": "linux",
  "rootfs": {
    "type": "layers",
    "diff_ids": [
      "sha256:4942a1abcbfa1c325b1d7ed93d3cf6020f555be706672308a4a4a6b6d631d2e7",
      "sha256:b58c5e8ccaba8886661ddd3b315989f5cf7839ea06bbe36547c6f49993b0d0aa",
      "sha256:743c70a5f809c27d5c396f7ece611bc2d7c85186f9fdeb68f70986ec6e4d165f",
      "sha256:316bbb8c58be42c73eefeb8fc0fdc6abb99bf3d5686dd5145fc7bb2f32790229",
      "sha256:3309d6da2bd696689a815f55f18db3f173bc9b9a180e5616faf4927436cf199d",
      "sha256:8d364403e7bf70d7f57e807803892edf7304760352a397983ecccb3e76ca39fa"
    ]
  }
}

```

And it's cracked wide open! Let's print this without the noise so it's easier to look at the chronology:

```bash
$ jq '.history[] .created_by' b324f85f8104bfebd1ed873e90437c0235d7a43f025a047d5695fe461da717c6.json
"/bin/sh -c #(nop) ADD file:d2abf27fe2e8b0b5f4da68c018560c73e11c53098329246e3e6fe176698ef941 in / "
"/bin/sh -c #(nop)  CMD [\"bash\"]"
"/bin/sh -c apt update -y"
"/bin/sh -c apt install -y curl openssl"
"/bin/sh -c #(nop) COPY file:2ca89eb39686ffcc3d2d87bbc9293559252cff471f80c2ed5d024b214f9a6fa3 in / "
"/bin/sh -c echo -n $(curl -s https://pastebin.com/raw/P9Nkw866) | openssl enc -aes-256-cbc -iter 10 -pass pass:$(cat /pass.txt) -out flag.enc"
"/bin/sh -c rm /pass.txt"
```

First command ran is apt update, standard, then we installed curl and openssl, then the main encryption, we got our flag from a pastebin link which gets encrypted later, got our password for encrypting the flag from pass.txt, then wrote out the encrypted flag.enc with aes, and removed the pass.txt file.
I checked the pastebin link and it had been removed, with no archives of it on wayback machine either, so probably removed intentionally.

hOwever, since we have the layers themselves, we can access the tar for the copy layer (`316bbb8c58be42c73eefeb8fc0fdc6abb99bf3d5686dd5145fc7bb2f32790229`), and the pass.txt will still be there! The latest rm layer (`8d364403e7bf70d7f57e807803892edf7304760352a397983ecccb3e76ca39fa`), after the encryption layer (`3309d6da2bd696689a815f55f18db3f173bc9b9a180e5616faf4927436cf199d`: this contains our flag.enc) only hides it in the final filesystem using docker's overlay. So that's `316bbb8c58be42c73eefeb8fc0fdc6abb99bf3d5686dd5145fc7bb2f32790229.tar`
Extracting it:
```bash
$ tar -xvf 316bbb8c58be42c73eefeb8fc0fdc6abb99bf3d5686dd5145fc7bb2f32790229.tar
pass.txt

$ cat pass.txt
d4428185a6202a1c5806d7cf4a0bb738a05c03573316fe18ba4eb5a21a1bc8ea
```

Let's get our encrypted flag.enc from the next layer: `3309d6da2bd696689a815f55f18db3f173bc9b9a180e5616faf4927436cf199d.tar`

```bash
$ tar -xvf 3309d6da2bd696689a815f55f18db3f173bc9b9a180e5616faf4927436cf199d.tar
flag.enc
```

With both the encrypted flag, and the recovered pass.txt used, we can decrypt our flag:

```bash
$ openssl enc -d -aes-256-cbc -iter 10 -pass "pass:$(cat pass.txt)" -in flag.enc
Well_D0ne_D0ckER_L@y3rs_Inspect0R
```
And there it is!
# FLAG
Well_D0ne_D0ckER_L@y3rs_Inspect0R
