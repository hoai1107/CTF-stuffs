from pwn import *
from socket import *
from struct import *

context.arch = 'amd64'
context.log_level = 'debug'

str1 = "4a 53 47 5d 41 45 03 54 5d 02 5a 0a 53 57 45 0d 05 00 5d 55 54 10 01 0e 41 55 57 4b 45 50 46 01"
str2 = "38 36 31 38 33 36 66 31 33 65 33 64 36 32 37 64 66 61 33 37 35 62 64 62 38 33 38 39 32 31 34 65"

num1 = bytes.fromhex("".join(str1.split()))
num2 = bytes.fromhex("".join(str2.split()))

print(xor(num1,num2))

#password = reverseengineericanbarelyforward
#unhash_key = goldfish


 












