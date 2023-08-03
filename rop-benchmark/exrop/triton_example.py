from __future__ import print_function
from triton import TritonContext, ARCH, Instruction, OPERAND, EXCEPTION
 
trace = [
    # (0x400000, b"\xc3"), # mov        rax, QWORD PTR [rip+0x13b8]
    (0x400000, b"\x48\x8b\x05\xb8\x13\x00\x00"), # mov        rax, QWORD PTR [rip+0x13b8]
    # (0x400007, b"\x48\x8d\x34\xc3"),             # lea        rsi, [rbx+rax*8]
    # (0x40000b, b"\x67\x48\x8D\x74\xC3\x0A"),     # lea        rsi, [ebx+eax*8+0xa]
    # (0x400011, b"\x66\x0F\xD7\xD1"),             # pmovmskb   edx, xmm1
    # (0x400015, b"\x89\xd0"),                     # mov        eax, edx
    # (0x400017, b"\x80\xf4\x99"),                 # xor        ah, 0x99
]
 
ctxt = TritonContext()
 
# Set the arch
ctxt.setArchitecture(ARCH.X86_64)
 
for (addr, opcode) in trace:

    # Build an instruction
    inst = Instruction()

    # Setup opcode
    inst.setOpcode(opcode)

    # Setup Address
    inst.setAddress(addr)

    # Process everything
    if ctxt.processing(inst) == EXCEPTION.FAULT_UD:
        print("Fail an instruction")

    print(inst)
    for op in inst.getOperands():
        print('    %s' % (op))
        if op.getType() == OPERAND.MEM:
            print('         base  : %s' % (op.getBaseRegister()))
            print('         index : %s' % (op.getIndexRegister()))
            print('         disp  : %s' % (op.getDisplacement()))
            print('         scale : %s' % (op.getScale()))
    print('')
