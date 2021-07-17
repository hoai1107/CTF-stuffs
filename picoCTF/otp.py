#from pwn import *
from socket import *
from struct import *

#context.arch = 'amd64'
#context.log_level = 'debug'

check = "bajbgfapbcclgoejgpakmdilalpomfdlkngkhaljlcpkjgndlgmpdgmnmepfikanepopbapfkdgleilhkfgilgabldofbcaedgfe"
character = "0123456789abcdef"
key = ""

gdb.execute('file ./otp')
gdb.execute('b *0x00005555555549bd')

cnt = 0
for i in check:
	for c in character:
		payload = key + c
		payload += (100 - len(payload))* "a"
		print(payload)

		command = "run " + payload
		gdb.execute(command)
		response = gdb.execute("x/s $rdi",False,True)
		s = response[17:17+100]

		if s[cnt]==i:
			key += c
			cnt += 1
			break

print(key)

flag = "ffadccb05b5892418ff068dd9d42231e8caf8ebb289ea1873f0a474cabe7ce598db77bac9dfef1d7c2b5af3c35bf5844c082"

xor_string = int(flag,16)^int(key,16)
print(bytearray.fromhex(xor_string).decode())

#picoCTF{cust0m_jumbl3s_4r3nt_4_g0Od_1d3A_42dad069}













