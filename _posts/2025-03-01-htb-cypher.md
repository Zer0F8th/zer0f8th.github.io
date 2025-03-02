---
title: "HTB Lab: Cypher"
date: 2025-02-21 10:00:00 +0000
image:
  path: preview.png
layout: post
media_subpath: /assets/posts/2025-03-01-htb-cypher
categories: [Linux, HTB-Medium]
tags: [HTB, HTB_Medium, Cypher-Injection, Neo4j, ffuf, Reverse-Shell, Java-Decompiler, Command-Injection, Credential-Reuse, APOC, Sudo-Misconfiguration, Linux]
description: "Cypher is a medium level Linux machine on HTB that teaches you how subtle misconfigurations in Neo4j and custom APOC functions can lead to devastating command injections. You’ll start by uncovering a suspicious JAR file in the webserver’s /testing directory, revealing a poorly handled curl call. From there, a clever Cypher injection in the login mechanism enables remote command execution. After pivoting from the neo4j account to graphasm by discovering re-used credentials, the final challenge is to exploit a tool with sudo privileges to read sensitive root-owned files. Players will gain valuable experience with Cypher injection, Neo4j internals, and creative ways to elevate privileges on a Linux system."
---

# Cypher

- Machine Name: Cypher
- Operating System: Linux
- Difficulty: Medium
- User Blood:  [l1nvx](https://app.hackthebox.com/users/634163)
- System Blood: [jkr](https://app.hackthebox.com/users/77141)

---
