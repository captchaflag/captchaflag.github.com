---
layout: post
title: "Hack You Too - Keygen Me?"
date: 2013-01-07 21:14
comments: true
categories: [bin]
author: stacks0n
---

## Challenge
You need the right key.

File: [keygen_me.exe](http://hackyou.ctf.su/files/keygen_me.exe)

## Analysis
Windows GUI executable. Simply takes one input and appears to check the result. When we enter junk, we get a message of ```xD Try again!```. Looking at the strings, it is not completely obvious where this is printed. However, there are not many user functions and eventually we see a call to [GetDlgItemTextA()](http://msdn.microsoft.com/en-us/library/ms645489%28VS.85%29.aspx) which stores user input from dialog box into a buffer.
```
.text:01391252                 call    ds:GetDlgItemTextA
```

Just following loading the user input into the buffer, we see manipulation of the data and a character by character comparison afterwards.
```
.text:01391260 loc_1391260:
.text:01391260                 mov     dl, [ebp+eax+String]
.text:01391264                 add     dl, al
.text:01391266                 xor     dl, byte ptr [ebp+eax+Hackplanet]
.text:0139126A                 inc     eax
.text:0139126B                 mov     [ebp+eax+key], dl
.text:0139126F                 cmp     eax, 11
.text:01391272                 jl      short loc_1391260
.text:01391274                 cmp     [ebp+key+1], 39
.text:01391278                 jnz     short loc_13912C5
.text:0139127A                 cmp     [ebp+key+2], 15
.text:0139127E                 jnz     short loc_13912C5
.text:01391280                 cmp     [ebp+key+3], 11
.text:01391284                 jnz     short loc_13912C5
.text:01391286                 cmp     [ebp+key+4], 1
.text:0139128A                 jnz     short loc_13912C5
.text:0139128C                 cmp     [ebp+key+5], 60
.text:01391290                 jnz     short loc_13912C5
.text:01391292                 mov     cl, 10
.text:01391294                 cmp     [ebp+key+6], cl
.text:01391297                 jnz     short loc_13912C5
.text:01391299                 mov     al, 8
.text:0139129B                 cmp     [ebp+key+7], al
.text:0139129E                 jnz     short loc_13912C5
.text:013912A0                 cmp     [ebp+key+8], 28
.text:013912A4                 jnz     short loc_13912C5
.text:013912A6                 cmp     [ebp+key+9], al
.text:013912A9                 jnz     short loc_13912C5
.text:013912AB                 cmp     [ebp+key+0Ah], 25
.text:013912AF                 jnz     short loc_13912C5
.text:013912B1                 cmp     [ebp+key+0Bh], cl
```

The following Ruby code reverses the above
```ruby
#!/usr/bin/env ruby

key = "Hackplanet"
solution = [0x27, 0x0f, 0x0b, 0x01, 0x3c, 0x0a, 0x08, 0x1c, 0x08, 0x19]

solution.each_index do |i|
    print (( key[i].ord ^ solution[i] ) - i).chr
end
puts ""
```

```bash
stacks0n@stacks0ns-MacBook-Pro:~> ./keygen_me.rb
omfgHacked
```

## Solution
omfgHacked
