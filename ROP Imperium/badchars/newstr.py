#!/usr/bin/env python3
from pwn import *
from struct import *

string = "flag.txt"
badchars = ['x','g','a','.']

for i in range (1,100):
	encoded = ""
	flag = True
	for j in range (0,len(string)):
		c = chr(ord(string[j])^i)
		if c in badchars:
			flag = False
			break
		else: 
			encoded += c
	if flag:
		#encoded = encoded[::-1]
		print(str(i))
		print(hex(int.from_bytes(encoded.encode("ascii"),"little")))
		exit()


