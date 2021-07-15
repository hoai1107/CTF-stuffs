#from pwn import *
from socket import *
from struct import *
import string
import gdb


#context.arch = 'amd64'
#context.log_level = 'debug'

#breakpoint = 0x56555992

flag = "picoCTF{"
number = "".join(str(i) for i in range (0,10))
character = string.ascii_lowercase + string.ascii_uppercase + "_}" + number
length = 8

gdb.execute('file ./brute')
gdb.execute('b *0x56555992')

while length<29:
	for c in character:
		payload = flag + c
		gdb.execute('run <<<'+payload)
		s = gdb.execute('x/x $ebp-0x14',False,True)
		res = s
		l = int(res[-3:-1],16)
		if l == length + 1:
			flag += c
			length += 1
			break

	if '}' in flag:
		break


print(flag + '}')
gdb.execute('quit')

#picoCTF{I_5D3_A11DA7_dd4ad7d3}








