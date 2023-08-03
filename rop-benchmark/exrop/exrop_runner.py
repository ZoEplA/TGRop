from pwn import *
from Exrop import Exrop
from io import StringIO
import time
import sys
from datetime import datetime 
from elftools.elf.elffile import ELFFile

binary = sys.argv[1]
ropchain_path = sys.argv[2]
if len(sys.argv) == 4:
    bad_chars = sys.argv[3]
check_regs_set_func_addr = 0
check_regs = 0
if(len(sys.argv) >= 4):
    check_regs_set_func_addr = int(sys.argv[3])
if(len(sys.argv) >= 5):
    check_regs = int(sys.argv[4])

# from elftools.elf.elffile import ELFFile
def find_rw_section(binary, section_name=".got.plt"):
    with open(binary, "rb") as bin_data:
        elf = ELFFile(bin_data)
        sec = elf.get_section_by_name(section_name)
        if not sec:
            sec = elf.get_section_by_name(".data")
        addr = sec['sh_addr']
        return addr

def get_func_addr(binary, function_name):
    with open(binary, "rb") as bin_data:
        elf = ELFFile(bin_data)
        sec = elf.get_section_by_name(".symtab")
        if sec is None:
            sec = elf.get_section_by_name(".dynsym")
        symbols_list = sec.get_symbol_by_name(function_name)
        if symbols_list is None:
            print("{} not found".format(function_name))
            exit(1)
        symbol = symbols_list[0]
        addr = symbol.entry['st_value']
        print("{} addr: {}".format(function_name, hex(addr)))
        return addr

begin = datetime.now() 
elf = ELF(binary)
rwaddr = elf.bss()
rop = Exrop(binary)
rop.find_gadgets(cache=False, num_process=8)
# execve is 59 syscall on x86_64
anaylsis_end = datetime.now() 
# chain = rop.syscall(59, ("/bin/fh", 0, 0), rwaddr)
# chain = rop.set_string({0x12345:"/bin/fh"})
# chain = rop.set_regs({'rdi':0x41414141, 'rsi': 0x42424242, 'rdx':0x43434343, 'rax':0x44444444, 'rbx': 0x45454545, 'rcx':0x4b4b4b4b, 'r8': 0x47474747, 'r9': 0x48484848, 'r10':0x49494949, 'r11': 0x4a4a4a4a, 'r12': 0x50505050, 'r13': 0x51515151, 'r14':0x52525252, 'r15': 0x53535353})
# chain = rop.set_regs({'rdi':0x41414141, 'rsi': 0x42424242, 'rdx':0x43434343, 'rcx':0x4b4b4b4b, 'r8': 0x47474747})

if(check_regs != 0):
    set_values = [0x100001, 0x100002, 0x100003, 0x100004, 0x100005, 0x100006]
    call_paras_list = []
    for i in range(check_regs):
        call_paras_list.append(set_values[i])
    chain = rop.func_call(check_regs_set_func_addr, call_paras_list)
else:
    
    # rw_address = find_rw_section(binary, section_name = '.data')
    # sys_func_addr = get_func_addr(binary, 'sys')
    # chain = rop.set_string({rw_address:"/bin/sh"})
    # chain += rop.func_call(sys_func_addr, [rw_address])

    chain = rop.syscall(59, ("/bin/fh", 0, 0), rwaddr)

chain_end = datetime.now() 
script_path = "{}.exrop.script".format(binary)
with open(script_path, 'w') as script:
    stdout = sys.stdout
    sys.stdout = StringIO()
    chain.dump()
    output = sys.stdout.getvalue()
    sys.stdout = stdout
    script.write(output)

with open(ropchain_path, 'wb') as ropchain_f:
    payload = chain.payload_str()
    ropchain_f.write(payload)

