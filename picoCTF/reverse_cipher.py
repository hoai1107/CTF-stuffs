from pwn import *
from socket import *
from struct import *

encrypt = "picoCTF{w1{1wq8/7376j.:}"

flag = "picoCTF{"

for i in range (8,24):
	if i & 1 == 0:
		c = ord(encrypt[i]) - 5
		flag += chr(c)
	else:
		c = ord(encrypt[i]) + 2
		flag += chr(c)

print(flag)			 













