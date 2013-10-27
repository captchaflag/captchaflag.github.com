---
layout: post
title: "Hack.lu 2013 - Packed"
date: 2013-10-27 15:39
author: stacks0n
comments: true
categories: files, python, xor
---

## Challenge
We just found a dead robot. It seems there is some useful data left but somehow it got confused with other data and now we don't know what's useful and what's junk. We just know there is only one way to go but there are many dead ends.

Here is the challenge: http://ctf.fluxfingers.net/static/downloads/packed/packed

## Hint
Think outside the box - being several types at once like an animal that can change its color. Excuse the inaccuracy, but that's what you're searching for.

## Analysis
We are provided with a file that appears to contain a bunch of different data and files packaged together. After a bit of basic analysis, we see the following:

* a string alluding to rot13 encryption
* strange looking text with a few instances of ("zip")
* PDF ("no hint here")
* Base64 encoded blob which happens to be an open office document ("no hint here")
 * embedded PNG ("no hint here") within the .odt 

If we rot13 the strange looking plaintext we find the following python script:

```python
cipher = "H51\\\'Ux2J&+(3Z;Uxcx0Xxs\x13h\x014$V!R($R>\t/)R!\x01<.\x13,N-aP4M4aRuG1-VuU0 GuH+a@0W=3R9\x01>(_0\x01,8C0Rx GuN6\"V|\x1ez
KZ3\x014$]}R!2\x1d4S?7\x1au\x1fxs\t_\x01xa\x13<Gx)R&Ip2J&\x0f93T#zj\x1c\x1ap\x13rk\x00g\x01e|\x13g\x19ju\x0ba\x18jt\x02o+xa\x13u\x01
xa\x13%S1/Gu\x03\x1b.\\:N7.\\:N4o\x13\x0cN-3\x133M9&\x13<Rx A2WjiZ{DvaX0Xjh\x136N6\"R!\x01\x07rC0p\x138a\x1dc22ieu\x161Fw+=-@0\x1bRa
\x13u\x01(3Z;UxcR\'F.s\x1c>D!s\x13<Rx,Z&R1/Tw+R"

n = 0 ;
import hashlib, sys;

try:
    key = sys.argv[1]

except IndexError :
    sys.exit("x\x9c\xf3N\xadT0T\xc8\xcd,.\xce\xccKW\xc8\xccSH,J/\x03\x00M\x97\x07\\".decode("zip"))

f = getattr(hashlib,"x\x9c\xcbM1\x05\x00\x02G\x01\x07".decode("zip"))

while n < (5 *10 **6 ):
    key = (f(key).digest());
    n = n + 1
    key = key[:5].upper()

while len(key) < len(cipher):
    key = key * 2
    plain ="".join (map (chr ,[ord (a )^ord (b )for a ,b in zip (cipher ,key )]))
try:
    exec plain
except:
    print "x\x9c\x0b/\xca\xcfKW\xf0N\xadT\x04\x00\x14d\x03x".decode("zip"), repr(plain)
```

There is another block of 256-bytes that we aren't entirely sure what to do with, but analyzing the code further its simply using a 5-character key to XOR decrypt the ciphertext. More than likely the plaintext that is being sent to exec() is going to be python code, so let's break out xortool to see if we can find a key. Note, we specify the most common character should be space.

```bash
% python xortool.py -l 5 -c ' ' ciphertext
1 possible key(s) of length 5:
!XA3U
```

Then, we can simply patch the python code to force the decryption. Patch the last block of code to to look like the following:
```python
key = "!XA3U"
while len(key) < len(cipher):
    key = key * 2
    plain ="".join (map (chr ,[ord (a )^ord (b )for a ,b in zip (cipher ,key )]))
try:
    print plain
    exec plain
```

Ah-hah, this now yields the following code:
```python
import sys
print "Key 2 = leetspeak(what do you call a file that is several file types at once)?"
if len(sys.argv) > 2:
    if hash(sys.argv[2])%2**32 == 2824849251:
        print "Coooooooool. Your flag is argv2(i.e. key2) concat _3peQKyRHBjsZ0TNpu"
else:
    print "argv2/key2 is missing"
```

Without the hint not sure we would have solved it, but they were hinting that key2 should be chameleon. So leetspeak() it and we get ch4m3l30n.


## Solution
```ch4m3l30n_3peQKyRHBjsZ0TNpu```
