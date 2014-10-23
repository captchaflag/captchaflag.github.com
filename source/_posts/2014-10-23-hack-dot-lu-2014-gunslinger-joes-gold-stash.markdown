---
layout: post
title: "Hack.lu 2014 - Gunslinger Joe's Gold Stash"
date: 2014-10-23 13:39
comments: true
author: darby
categories: reversing
---

## Challenge

Silly Gunslinger Joe has learned from his mistakes with his private terminal and
now tries to remember passwords. But he's gotten more paranoid and chose to
develope an additional method: protect all his private stuff with a secure
locking mechanism that no one would be able to figure out! He's so confident
with this new method that he even started using it to protect all his precious
gold. So … we better steal all of it!

SSH: joes_gold@wildwildweb.fluxfingers.net

PORT: 1415

PASSWORD: 1gs67uendsx71xmma8

## Analysis

Provided with a regular shell. There is a set uid/gid program 'gold_stash' for
gold group and a FLAG owned by gold.

```
joes_gold@goldstash:~$ id
uid=1000(joes_gold) gid=1000(joes_gold) groups=1000(joes_gold)

joes_gold@goldstash:~$ ls -al
drwxr-xr-x 2 joes_gold joes_gold  4096 Oct  6 23:09 .
drwxr-xr-x 3 root      root       4096 Oct  6 22:56 ..
-rw-r--r-- 1 joes_gold joes_gold  3106 Feb 20  2014 .bashrc
-r-------- 1 gold      gold         46 Oct  6 23:04 FLAG
-rwsr-sr-x 1 gold      gold      13186 Oct  6 23:03 gold_stash

joes_gold@goldstash:~$ id -u gold
1001
```

Here is the decompiled code of gold_stash:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __uid_t v3; // er12@7
  __uid_t v4; // ebx@7
  __uid_t v5; // eax@7
  int result; // eax@8
  __int64 v7; // rcx@8
  char *argva; // [sp+0h] [bp-230h]@7
  __int64 v9; // [sp+8h] [bp-228h]@7
  char username; // [sp+10h] [bp-220h]@1
  char password; // [sp+110h] [bp-120h]@1
  __int64 v12; // [sp+218h] [bp-18h]@1

  v12 = *MK_FP(__FS__, 0x28LL);
  memset(&username, 0, 0x100uLL);
  memset(&password, 0, 0x100uLL);
  puts("          (_/-------------_______________________)");
  puts("          `|  /~~~~~~~~~~\\                       |");
  puts("           ;  |--------(-||______________________|");
  puts("           ;  |--------(-| ____________|");
  puts("           ;  \\__________/'");
  puts("         _/__         ___;");
  puts("      ,~~    |  __--~~       Gunslinger Joe's");
  puts("     '        ~~| (  |       Private Stash of Gold");
  puts("    '      '~~  `____'");
  puts("   '      '");
  puts("  '      `            Password Protection activated!");
  puts(" '       `");
  puts("'--------`");
  printf("Username: ", 0LL);
  fflush(_bss_start);
  read(0, &username, 0xFFuLL);
  printf("Password: ", &username);
  fflush(_bss_start);
  read(0, &password, 0xFFuLL);
  if ( strchr(&username, 0xA) )
    *strchr(&username, 0xA) = 0;
  if ( strchr(&password, 0xA) )
    *strchr(&password, 0xA) = 0;
  if ( !strcmp(&username, "Joe") && !strcmp(&password, "omg_joe_is_so_rich") )
  {
    puts("Access granted!");
    v3 = geteuid();
    v4 = geteuid();
    v5 = geteuid();
    setresuid(v5, v4, v3);
    argva = "/bin/sh";
    v9 = 0LL;
    execve("/bin/sh", &argva, 0LL);
  }
  puts("Authentication failed!");
  result = 0;
  v7 = *MK_FP(__FS__, 0x28LL) ^ v12;
  return result;
}
```

The expected username and password don't work. However, they work in the
following cases:

* running strace
* running gdb
* running the binary on a local VM (Linux ubuntu 3.5.0-23-generic)
* copying the binary and running it on the remote VM

So, it's something about running the box in its native environment that makes it
work.  We found a kernel module on the box...

```
joes_gold@goldstash:~$ lsmod
Module                  Size  Used by
nfnetlink              14606  0 
bluetooth             391136  0 
joe                    12678  0 
ppdev                  17671  0 
serio_raw              13462  0 
i2c_piix4              22155  0 
parport_pc             32701  0 
lp                     17759  0 
parport                42348  3 lp,ppdev,parport_pc
mac_hid                13205  0 
psmouse               106678  0 
pcnet32                41545  0 
mii                    13934  1 pcnet32
joes_gold@goldstash:~$ uname -a
Linux goldstash 3.13.0-36-generic #63-Ubuntu SMP Wed Sep 3 21:30:07 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
joes_gold@goldstash:~$ ls /lib/modules/3.13.0-36-generic/kernel/joe/joe.ko
/lib/modules/3.13.0-36-generic/kernel/joe/joe.ko
joes_gold@goldstash:~$ 
```

The joe kernel module has functions such as:

* joe
* findshit
* lolcred
* fuqstring

There are references to the password ("omg_joe_is_so_rich") which appear to find
it in userland memory. It then appears to change it. The string is modified in
user input.

```c
__int64 __fastcall joe(__int64 a1, __int64 a2)
{
  __int64 v2; // rdx@1
  __int64 v3; // r14@1
  __int64 v4; // r12@1
  __int64 v5; // rax@1
  __int64 v6; // rbx@1
  int v7; // er13@1
  __int64 v8; // rax@1
  bool v9; // cf@1
  bool v10; // zf@1
  __int64 v12; // rsi@3
  signed __int64 v13; // rcx@3
  __int64 v14; // rdi@3
  signed __int64 v15; // rsi@6
  signed __int64 v16; // rax@6
  bool v17; // zf@12
  signed __int64 v18; // rcx@13
  __int64 v19; // rsi@13
  __int64 v20; // rdi@13

  _fentry__(a1);
  v3 = v2;
  v4 = a2;
  LODWORD(v5) = kmem_cache_alloc_trace(*((_QWORD *)&kmalloc_caches + 0x20000008), 0x80D0LL, 0x100LL);
  v6 = v5;
  v7 = ((int (__fastcall *)(_QWORD, __int64, __int64))*(&o_read + 0x40000000))((unsigned int)a1, a2, v3);
  copy_from_user(v6, a2, 0xFFLL);
  v8 = *(_QWORD *)(current_task + 0x4B0LL);
  v9 = *(_DWORD *)(v8 + 0x14) < 0x3E9u;
  v10 = *(_DWORD *)(v8 + 0x14) == 0x3E9;
  if ( *(_DWORD *)(v8 + 0x14) != 0x3E9 )
    goto LABEL_2;
  v12 = v6;
  v13 = 0x12LL;
  v14 = (__int64)"omg_joe_is_so_rich";
  do
  {
    if ( !v13 )
      break;
    v9 = *(_BYTE *)v12 < *(_BYTE *)v14;
    v10 = *(_BYTE *)v12++ == *(_BYTE *)v14++;
    --v13;
  }
  while ( v10 );
  v15 = 1LL;
  v16 = 0LL;
  if ( (!v9 && !v10) == v9 )
  {
    while ( 1 )
    {
      *(_BYTE *)(v6 + v16) = xor_key[v16] ^ (*(_BYTE *)(v6 + v16) - 4);
      if ( v15 == 0x12 )
        break;
      v16 = v15++;
    }
LABEL_10:
    copy_to_user(v4, v6, 0x12LL);
    goto LABEL_2;
  }
  while ( 1 )
  {
    *(_BYTE *)(v6 + v16) = xor_key[v16] ^ (*(_BYTE *)(v6 + v16) - 4);
    v17 = v15 == 0x12;
    if ( v15 == 0x12 )
      break;
    v16 = v15++;
  }
  v18 = 0x12LL;
  v19 = v6;
  v20 = (__int64)"omg_joe_is_so_rich";
  do
  {
    if ( !v18 )
      break;
    v17 = *(_BYTE *)v19++ == *(_BYTE *)v20++;
    --v18;
  }
  while ( v17 );
  if ( v17 )
    goto LABEL_10;
LABEL_2:
  kfree(v6);
  return v7;
}
```

The fuqstring function (in-lined above) appears to do a simple modification of
the target string:

```
xor_key         db '123456789012445678',0

char * fuqstring(char *buffer)
{
  int counter;
  int index;

  counter = 1;
  for ( index = 0; ; index = counter++ )
  {
    buffer[index] = xor_key[index] ^ (buffer[index] - 4);
    if ( counter == 18 )
      break;
  }
  return buffer;
}
```

## Solution

This code gives the password:

```python
#!/usr/bin/env python
userdata = "omg_joe_is_so_rich"
xorkey =   "123456789012445678"

assert(len(userdata) == len(xorkey))

index = 0
res = ""
for userbyte in userdata:
  res += chr(4+(ord(userbyte) ^ ord(xorkey[index])))
  index += 1
print res

OUTPUT:
bcXoc]VkTGrE_oKcXT
```

Providing the password gives us a shell running as gold.

```text
joes_gold@goldstash:~$ ./gold_stash 
          (_/-------------_______________________)
          `|  /~~~~~~~~~~\                       |
           ;  |--------(-||______________________|
           ;  |--------(-| ____________|
           ;  \__________/'
         _/__         ___;
      ,~~    |  __--~~       Gunslinger Joe's
     '        ~~| (  |       Private Stash of Gold
    '      '~~  `____'
   '      '
  '      `            Password Protection activated!
 '       `
'--------`
Username: Joe
Password: bcXoc]VkTGrE_oKcXT
Access granted!
$ cat FLAG
flag{joe_thought_youd_never_find_that_module}
$ 
```
