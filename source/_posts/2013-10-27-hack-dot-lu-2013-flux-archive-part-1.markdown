---
layout: post
title: "Hack.lu 2013 - Flux Archive Part 1"
date: 2013-10-27 15:42
authors: stacks0n
comments: true
categories: reversing, brute
---

## Challenge
These funny humans try to exclude us from the delicious beer of the Oktoberfest! They made up a passcode for everyone who wants to enter the Festzelt. Sadly, our human informant friend could not learn the passcode for us. But he heard a conversation between two drunken humans, that they were using the same passcode for this intercepted archive file. They claimed that the format is is absolutely secure and solves any kind of security issue. It's written by this funny hacker group named FluxFingers. Real jerks if you ask me. Anyway, it seems that the capability of drunken humans to remember things is limited. So they just used a 6 character passcode with only numbers and upper-case letters. So crack this passcode and get our ticket to their delicious german beer!

Here is the challenge: https://ctf.fluxfingers.net/static/downloads/fluxarchiv/hacklu2013_archiv_challenge1.tar.gz

## Analysis
Provided with a 64-bit ELF and a data file.

```
stacks0n@ubuntu:~/Desktop$ ./archiv

################################################################################

FluxArchiv - solved security since 2007!
Written by sqall - leading expert in social-kernel-web-reverse-engineering.

################################################################################

Unknown or invalid command.

Usage: ./archiv <command> <archiv> <password> <file>
commands:
-l <archiv> <password> - lists all files in the archiv.
-a <archiv> <password> <file> - adds a file to the archiv (when archiv does not exist create a new archiv).
-x <archiv> <password> <filename> - extracts the given filename from the archiv.
-d <archiv> <password> <filename> - delete the given filename from the archiv.
```

Presumably, we could try to brute force the entire key space (36^6) but that might take a while when trying to execute the program. So let's look into some of the key functions. Tracing backwards from the output of "Given password is not correct" we target verifyArchiv()

### verifyArchiv
This method reads 0x14 (20) bytes from the archive file starting at offset 0xC (12) which is our target hash to verify that the password is accurate. It starts by grabbing bytes from hash_password (SHA-1 sum of password) out of order, but in a predictable manner. Look at the python code for that order. Then, the byte stream of the hash is run through SHA-1 and compared against the target. Thus, we can brute force the entire key space only running the code necessary to find the target.

## Code
```python
#!/usr/bin/env python

import hashlib
import string
import itertools

def bruteforce(charset, maxlength):
    return (''.join(candidate)
        for candidate in itertools.chain.from_iterable(itertools.product(charset, repeat=i)
        for i in range(maxlength, maxlength + 1)))

for attempt in bruteforce(string.digits + string.ascii_uppercase, 6):
    hash = hashlib.sha1(attempt).digest()
    hash_scramble = hash[0] + hash[7] + hash[14] + hash[1] + hash[8] + hash[15] + hash[2] + hash[9] + hash[16] + hash[3] + hash[10] + hash[17] + hash[4] + hash[11] + hash[18] + hash[5] + hash[12] + hash[19] + hash[6] + hash[13]
    new_hash = hashlib.sha1(hash_scramble).hexdigest()
    if new_hash == "372942df2712824505d8171f4f0bcb14153d39ba":
        print "Found passphrase: " + attempt
        break
```

```
stacks0n@ubuntu:~/Desktop$ python fluxarchiv.py 
Found passphrase: PWF41L

stacks0n@ubuntu:~/Desktop$ ./archiv -l FluxArchiv.arc PWF41L

################################################################################

FluxArchiv - solved security since 2007!
Written by sqall - leading expert in social-kernel-web-reverse-engineering.

################################################################################

Filename:                                               Size in archiv:
--------------------------------------------------------------------------------
attentionzombie.mp3                                                     22 kB
Did_You_Know.jpg                                                        139 kB
fluxfingers.png                                                 9 kB
th_oh-noes-everybody-panic.gif                                                  131 kB

stacks0n@ubuntu:~/Desktop$ ls -alh attentionzombie.mp3 Did_You_Know.jpg fluxfingers.png th_oh-noes-everybody-panic.gif 
-rw-rw-r-- 1 stacks0n stacks0n  23K Oct 23 04:30 attentionzombie.mp3
-rw-rw-r-- 1 stacks0n stacks0n 135K Oct 23 04:30 Did_You_Know.jpg
-rw-rw-r-- 1 stacks0n stacks0n 9.0K Oct 23 04:31 fluxfingers.png
-rw-rw-r-- 1 stacks0n stacks0n 127K Oct 23 04:31 th_oh-noes-everybody-panic.gif
```

Nothing stands out as to what the flag might be. Okay, I'm dumb it is the password :)

## Solution
PWF41L
