---
layout: post
title: "Hack.lu 2013 - Flux Archive Part 2"
date: 2013-10-27 15:46
comments: true
author: stacks0n
categories: reversing, rc4, brute
---
## Challenge
These sneaky humans! They do not just use one passcode, but two to enter the Festzelt. We heard that the passcode is hidden inside the archive file. It seems that the FluxFingers overrated their programming skill and had a major logical flaw in the archive file structure. Some of the drunken Oktoberfest humans found it and abused this flaw in order to transfer hidden messages. Find this passcode so we can finally drink their beer!

## Analysis

Somewhere in the archive there is some hidden data. Playing around with the tool, I notice that when we delete archives the file size does not change. It must just leave the file entry data but delete the file itself.

```bash
% ./archiv -a myarchive.arc 123456 test 

################################################################################

FluxArchiv - solved security since 2007!
Written by sqall - leading expert in social-kernel-web-reverse-engineering.

################################################################################

Archiv myarchive.arc successfully created.

Progress:
0% ... 10% ... 20% ... 30% ... 40% ... 50% ... 60% ... 70% ... 80% ... 90% ... 100%

File test successfully added to the archiv.

% ls -al myarchive.arc
-rw-rw-r-- 1 stacks0n stacks0n 2112 Oct 23 20:39 myarchive.arc

% ./archiv -d myarchive.arc 123456 test 

################################################################################

FluxArchiv - solved security since 2007!
Written by sqall - leading expert in social-kernel-web-reverse-engineering.

################################################################################

File test successfully deleted from the archiv.

% ls -al myarchive.arc
-rw-rw-r-- 1 stacks0n stacks0n 2112 Oct 23 20:39 myarchive.arc
```

Looking at sanitizeFilename(), file entries begin at offset 0x20 and there is a magic value of "FluXL1sT". The filenames are RC4 encrypted with the key being the SHA-1 sum of the archive password. Setting a breakpoint in sanitizeFilename() towards the end of the function, we notice a number of files that are simply empty string. It would appear that they are simply cleared out when deleted.

I wonder if we can simply just encrypt a new filename and replace the entry to access the file without having to learn anything else about the file format. Turns out that I struggled with that, but when decrypting blocks in the file noticed my plaintext being displayed. So rather than actually figure out the format, lets just brute force decrypting blocks and see if we get lucky.

```ruby
#!/usr/bin/env ruby

require 'rc4'
require 'digest/sha1'

f = File.open("FluxArchiv.arc", "r")
success = false

password = "PWF41L"
key = Digest::SHA1.digest(password)
offset = 0

ciphertext = f.read(8)
while offset < f.size
    f.seek(offset)
    ciphertext = f.read(1024)
    dec = RC4.new(key)
    cleartext = dec.decrypt(ciphertext)

    if cleartext.match(/^[\w\s]{6}/) and cleartext.match(/key|flag/i)
        puts cleartext
    end

    offset += 8
end
```

## Solution
```bash
% ruby fluxarchiv2.rb
e electron and the switch, the
beauty of the baud.  We make use of a service already existing without paying
for what could be dirt-cheap if it wasn't run by profiteering gluttons, and
you call us criminals.  We explore... and you call us criminals.  We seek
after knowledge... and you call us criminals.  We exist without skin color,
without nationality, without religious bias... and you call us criminals.
You build atomic bombs, you wage wars, you murder, cheat, and lie to us
and try to make us believe it's for our own good, yet we're the criminals.

Yes, I am a criminal.  My crime is that of curiosity.  My crime is
that of judging people by what they say and think, not what they look like.
My crime is that of outsmarting you, something that you will never forgive me
for.

I am a hacker, and this is my manifesto.  You may stop this individual,
but you can't stop us all... after all, we're all alike.

+++The Mentor+++

Flag: D3letinG-1nd3x_F4iL
```

```D3letinG-1nd3x_F4iL```
