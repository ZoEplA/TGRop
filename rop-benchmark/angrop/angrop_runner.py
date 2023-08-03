from angr import Project
import angrop
import sys
from io import StringIO
from multiprocessing import cpu_count
from datetime import datetime 
from elftools.elf.elffile import ELFFile

binary = sys.argv[1]
ropchain_path = sys.argv[2]


check_regs_set_func_addr = 0
check_regs = 0
if(len(sys.argv) >= 4):
    check_regs_set_func_addr = int(sys.argv[3])
if(len(sys.argv) >= 5):
    check_regs = int(sys.argv[4])


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
project = Project(binary)
rop = project.analyses.ROP()
if len(sys.argv) == 4:
    import binascii
    bad_chars = sys.argv[3]
    rop.set_badbytes(list(binascii.unhexlify(bad_chars)))
# rop.find_gadgets_single_threaded(show_progress=True)
rop.find_gadgets(show_progress=True)
anaylsis_end = datetime.now() 


if(check_regs != 0):
    set_values = [0x100001, 0x100002, 0x100003, 0x100004, 0x100005, 0x100006]
    call_paras_list = []
    for i in range(check_regs):
        call_paras_list.append(set_values[i])
    chain = rop.func_call(check_regs_set_func_addr, call_paras_list)
else:
    # rw_address = find_rw_section(binary, section_name = '.data')
    # sys_func_addr = get_func_addr(binary, 'sys')
    # chain = rop.write_to_mem(rw_address, b"/bin/sh\x00")
    # chain += rop.func_call(sys_func_addr, [rw_address])
    
    chain = rop.execve(b"/bin/fh\x00")

# chain = rop.execve(b"/bin/fh\x00")
# chain = rop.set_regs(rdi=0x62636465, rsi=0x63646566, rdx=0x64656667, rcx=0x64656668, r8=0x64656669)
# chain = rop.write_to_mem(0x100000, b"/bin/sh\x00")

chain_end = datetime.now() 

script_path = "{}.angrop.script".format(binary)
with open(script_path, 'w') as script:
    stdout = sys.stdout
    sys.stdout = StringIO()
    chain.print_payload_code()
    output = sys.stdout.getvalue()
    sys.stdout = stdout
    script.write(output)

with open(ropchain_path, 'wb') as ropchain_f:
    payload = chain.payload_str()
    ropchain_f.write(payload)
