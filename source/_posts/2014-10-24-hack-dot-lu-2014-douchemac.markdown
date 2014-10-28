---
layout: post
title: "Hack.lu 2014 - Douchemac"
date: 2014-10-24 14:57
comments: true
categories: [hacklu, crypto]
author: m3g4tr0n
---
## Challenge
* by martin (Crypto)
* 200 (+100) Points

Our companion Jesse James shot a carrier pigeon. It had a letter containing weird characters. Maybe it has something todo with the local gold mine. 

Download

## Analysis
The download is a pcap of D-BUS traffic.

Eventually, you find:

```text
------------------------------------------------------
|        SIMPLE SECURE NOTES STORAGE SYSTEM            |
| DOUCHEMAC-SHA256-CBC Authentication System           |
| 1. start a session (valid 10 min)                    |
| 2. authenticate                                      |
| 3. work                                              |
|                                                      |
|                                                      |
| NULL padding                                         |
 ------------------------------------------------------
Use ID: 75288142666
Use Nonce: z9TxSOvwZ21KDcHQeTef8Q== to xor your key!

```

There are two TCP Flows in the PCAP:

One:

```text
.AUTH EXTERNAL 363636
REJECTED EXTERNAL DBUS_COOKIE_SHA1 ANONYMOUS
AUTH DBUS_COOKIE_SHA1 363636
REJECTED EXTERNAL DBUS_COOKIE_SHA1 ANONYMOUS
AUTH ANONYMOUS 6c69626462757320312e382e38
OK aba45dc8a0c4d0ff480a9adc5433de97
BEGIN
l...........n.....o...../org/freedesktop/DBus.....s.....org.freedesktop.DBus......s.....org.freedesktop.DBus......s.....Hello...l...
.......=.....s.....:1.31.....u.......g..s....s.....org.freedesktop.DBus........:1.31.l.................o...../org/freedesktop/DBus.....s.....org.freedesktop.DBus......s.....org.freedesktop.DBus......s.....GetNameOwner......g..s......test.test123.Server.l...
.............o...../org/freedesktop/DBus.....s.....org.freedesktop.DBus......s.....NameAcquired......s.....:1.31.....g..s....s.....org.freedesktop.DBus........:1.31.l...
.......=.....s.....:1.31.....u.......g..s....s.....org.freedesktop.DBus........:1.30.l...........c.....o...../Server...s.....:1.30.....s.#...org.freedesktop.DBus.Introspectable.......s.
...Introspect......l.................o...../org/freedesktop/DBus.....s.....org.freedesktop.DBus......s.....org.freedesktop.DBus......s.....GetNameOwner......g..s......test.test123.Server.l.................s.....:1.31.....u.......g..s....s.....:1.30.......<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node name="/Server">
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg direction="out" type="s" />
    </method>
  </interface>
  <interface name="test.test123.Interface">
    <method name="dbus_genrnd">
      <arg direction="in"  type="s" name="id" />
      <arg direction="out" type="s" />
    </method>
  </interface>
  <interface name="test.test123.Server">
    <method name="dbus_authc">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="msg" />
      <arg direction="in"  type="s" name="iv" />
      <arg direction="in"  type="s" name="tag" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_auths">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="msg" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_time">
      <arg direction="in"  type="s" name="id" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_list">
      <arg direction="in"  type="s" name="id" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_put">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="filename" />
      <arg direction="in"  type="s" name="text" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_get">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="filename" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_start">
      <arg direction="out" type="s" />
    </method>
  </interface>
</node>
.l...
.......=.....s.....:1.31.....u.......g..s....s.....org.freedesktop.DBus........:1.30.l...........c.....o...../Server...s.....:1.30.....s.#...org.freedesktop.DBus.Introspectable.......s.
...Introspect......l.................s.....:1.31.....u.......g..s....s.....:1.30.......<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node name="/Server">
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg direction="out" type="s" />
    </method>
  </interface>
  <interface name="test.test123.Interface">
    <method name="dbus_genrnd">
      <arg direction="in"  type="s" name="id" />
      <arg direction="out" type="s" />
    </method>
  </interface>
  <interface name="test.test123.Server">
    <method name="dbus_authc">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="msg" />
      <arg direction="in"  type="s" name="iv" />
      <arg direction="in"  type="s" name="tag" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_auths">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="msg" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_time">
      <arg direction="in"  type="s" name="id" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_list">
      <arg direction="in"  type="s" name="id" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_put">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="filename" />
      <arg direction="in"  type="s" name="text" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_get">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="filename" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_start">
      <arg direction="out" type="s" />
    </method>
  </interface>
</node>
.l...........3.....o...../Server...s.....:1.30.....s.
...dbus_start......l.................s.....:1.31.....u.......g..s....s.....:1.30....... ------------------------------------------------------
|        SIMPLE SECURE NOTES STORAGE SYSTEM            |
| DOUCHEMAC-SHA256-CBC Authentication System           |
| 1. start a session (valid 10 min)                    |
| 2. authenticate                                      |
| 3. work                                              |
|                                                      |
|                                                      |
| NULL padding                                         |
 ------------------------------------------------------
Use ID: 75288142666
Use Nonce: z9TxSOvwZ21KDcHQeTef8Q== to xor your key!
.
```


The other:

```text
.AUTH EXTERNAL 363636
REJECTED EXTERNAL DBUS_COOKIE_SHA1 ANONYMOUS
AUTH DBUS_COOKIE_SHA1 363636
REJECTED EXTERNAL DBUS_COOKIE_SHA1 ANONYMOUS
AUTH ANONYMOUS 6c69626462757320312e382e38
OK aba45dc8a0c4d0ff480a9adc5433de97
BEGIN
l...........n.....o...../org/freedesktop/DBus.....s.....org.freedesktop.DBus......s.....org.freedesktop.DBus......s.....Hello...l...
.......=.....s.....:1.32.....u.......g..s....s.....org.freedesktop.DBus........:1.32.l.................o...../org/freedesktop/DBus.....s.....org.freedesktop.DBus......s.....org.freedesktop.DBus......s.....GetNameOwner......g..s......test.test123.Server.l...
.............o...../org/freedesktop/DBus.....s.....org.freedesktop.DBus......s.....NameAcquired......s.....:1.32.....g..s....s.....org.freedesktop.DBus........:1.32.l...
.......=.....s.....:1.32.....u.......g..s....s.....org.freedesktop.DBus........:1.30.l...........c.....o...../Server...s.....:1.30.....s.#...org.freedesktop.DBus.Introspectable.......s.
...Introspect......l.................o...../org/freedesktop/DBus.....s.....org.freedesktop.DBus......s.....org.freedesktop.DBus......s.....GetNameOwner......g..s......test.test123.Server.l.................s.....:1.32.....u.......g..s....s.....:1.30.......<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node name="/Server">
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg direction="out" type="s" />
    </method>
  </interface>
  <interface name="test.test123.Interface">
    <method name="dbus_genrnd">
      <arg direction="in"  type="s" name="id" />
      <arg direction="out" type="s" />
    </method>
  </interface>
  <interface name="test.test123.Server">
    <method name="dbus_authc">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="msg" />
      <arg direction="in"  type="s" name="iv" />
      <arg direction="in"  type="s" name="tag" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_auths">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="msg" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_time">
      <arg direction="in"  type="s" name="id" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_list">
      <arg direction="in"  type="s" name="id" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_put">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="filename" />
      <arg direction="in"  type="s" name="text" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_get">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="filename" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_start">
      <arg direction="out" type="s" />
    </method>
  </interface>
</node>
.l...
.......=.....s.....:1.32.....u.......g..s....s.....org.freedesktop.DBus........:1.30.l...........c.....o...../Server...s.....:1.30.....s.#...org.freedesktop.DBus.Introspectable.......s.
...Introspect......l.................s.....:1.32.....u.......g..s....s.....:1.30.......<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node name="/Server">
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg direction="out" type="s" />
    </method>
  </interface>
  <interface name="test.test123.Interface">
    <method name="dbus_genrnd">
      <arg direction="in"  type="s" name="id" />
      <arg direction="out" type="s" />
    </method>
  </interface>
  <interface name="test.test123.Server">
    <method name="dbus_authc">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="msg" />
      <arg direction="in"  type="s" name="iv" />
      <arg direction="in"  type="s" name="tag" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_auths">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="msg" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_time">
      <arg direction="in"  type="s" name="id" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_list">
      <arg direction="in"  type="s" name="id" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_put">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="filename" />
      <arg direction="in"  type="s" name="text" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_get">
      <arg direction="in"  type="s" name="id" />
      <arg direction="in"  type="s" name="filename" />
      <arg direction="out" type="s" />
    </method>
    <method name="dbus_start">
      <arg direction="out" type="s" />
    </method>
  </interface>
</node>
.l...........?.....o...../Server...s.....:1.30.....s.....dbus_time.........g..s......75288142666.l.................s.....:1.32.....u.......g..s....s.....:1.30...
...1412688735.91.l...........?.....o...../Server...s.....:1.30.....s.....dbus_genrnd.......g..s......75288142666.l.................s.....:1.32.....u.......g..s....s.....:1.30.......+pVgvsPDX1LI7xDc/AS9Fg==
.

```

Here, we installed D-Feet, a d-bus debugger that can be used for remote interaction.

Using D-Feet to interact with the server, we called the help function, which returned:
```text
 ------------------------------------------------------
|        SIMPLE SECURE NOTES STORAGE SYSTEM            |
| DOUCHEMAC-SHA256-CBC Authentication System           |
|                                                      |
| SPEC:                                                |
|   blocksize = 16                                     |
|   k = k ^ nonce                                      |
|   while len(M) % 16: M || NULL                       |
|   M = M_0 || M_1 ...                                 |
|   tag_0 = sha256(k || M_0 ^ iv)                      |
|   tag_i = sha256(k || M_i ^ tag_i-1)                 |
|                                                      |
| FUNCS:                                               |
|   start : start session                              |
|   genrnd: get random numer                           |
|   time  : get time                                   |
|   list  : list files                                 |
|   put   : put file                                   |
|   get   : get file                                   |
|   auths : server authentication                      |
|   authc : client authentication                      |
|                                                      |
| NOTE:                                                |
|   session times out                                  |
|   connection limit                                   |
 ------------------------------------------------------
```

Calling the start function gives us a session ID and a nonce:

```

\r\nUse ID: 688383258476362303\r\nUse Nonce: 2bH5BJ5gR4FPnw8JIPvMgw== to xor your key!\r\n'

```
It became apparent that we needed to authenticate to the server by calling authc(id, msg, iv, tag) where msg is a base64-encoded raw message, the iv we used, and the tag of the message as generated by the algorithm in "SPEC" of the help response.
Auths(id, msg) would return an iv and tag of msg, but when we try to feed this output directly into authc(), we receive:

```

u'IV : eDmGlE34dc6xjskpRtaCQg==\r\nMsg: YmxhaA==\r\nTag: GGzDwlaGGl+MBlMO2Svbmw==\r\n'
u'Please choose another message!\r\n'
```
Next, we tried exploiting the fact that, given the algorithm they are using, we could flip a bit in the first block of the message and flip the corresponding bit in the IV without affecting the tag of the message. So we gave auths() the msg in the first line below, and then flipped a bit in the provided IV and in the original msg (line 2). We gave this to authc() and received line 3.

```

u'IV : JNuQTRBq+1uYePtwjyt8KQ==\r\nMsg: AAAAAAAAAAAAAAAAAAAAAA==\r\nTag: 78Eb6hYOZFu4yOGNVWxjDQ==\r\n'
"215791365151423835", 'AQAAAAAAAAAAAAAAAAAAAA==', 'JduQTRBq+1uYePtwjyt8KQ==', '78Eb6hYOZFu4yOGNVWxjDQ=='
u'Please choose a different message length (blocks: 1)!\r\n'

```

Now we knew that the message we give to authc() needs to be of different length than the one we give to auths(). Finally, we saw that we could extend the message in the following way:

```

 if M_i = M_0 ^ iv ^ tag_0
 then tag_1 = sha256(k || M_i ^ tag_0) = sha256(k || M_0 ^ iv ^ tag_0 ^ tag_0) = tag_0

```

So, we generated the following from auths() using a message block of all 0's:

```

u'IV : qyvebQDUhwtfPApJ/liLzQ==\r\nMsg: AAAAAAAAAAAAAAAAAAAAAA==\r\nTag: HBF3ALjqxh6DncNXUxU8EA==\r\n'

```

and then we could append a second block onto our message, M_1 = M_0 ^ iv ^ tag. Giving this longer message to authc() along with the same tag and iv yielded authentication:1.

We then simply needed to call list() and decode the response to get the name of the file containing the flag, secret.txt. We then encoded secret.txt and sent the get(id, file) command, which returned the flag:

u'flag{c6Lnm39r950dlh6WzeIN}\n'


helpful script:
```python
import base64

def flip_bit(msg):
  s = bytearray(base64.b64decode(msg))
  s[0] = s[0] ^1
  return base64.b64encode(s)
 
def xor(m1, m2):
  s1 = bytearray(base64.b64decode(m1))
  s2 = bytearray(base64.b64decode(m2))
  return base64.b64encode(bytearray(x^y for x,y in zip(s1,s2)))

def cat(m1,m2):
  s1 = bytearray(base64.b64decode(m1))
  s2 = bytearray(base64.b64decode(m2))
  return base64.b64encode(s1+s2)

#u'IV : EgPPG3/6IoWYHDK7/ySL1g==\r\nMsg: AAAAAAAAAAAAAAAAAAAAAA==\r\nTag: 31HfnMcBiAZj8CgMaZC78w==\r\n'
# want msg = (M_0 || M_0 ^ iv ^ tag_0)
# return msg, iv, tag
def mk_params(iv, msg, tag):
  m_i = cat(msg, xor(xor(msg, iv), tag) )
  print "'%s', '%s', '%s'"%(m_i, iv, tag)
```
