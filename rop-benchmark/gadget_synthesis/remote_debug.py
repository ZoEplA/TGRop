import subprocess

# 调试程序的路径和参数
program_path = '/ssd/home/rop/rop-benchmark-master/binaries/x86/reallife/vuln/centos-7.1810/ata_id.bin'
program_args = b'/ssd/home/rop/rop-benchmark-master/gadget_synthesis/targets/target_template/stack.bin'

# 启动 GDB
gdb_cmd = ['gdb'] + [program_path]
gdb_proc = subprocess.Popen(gdb_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

# 等待 GDB 启动并设置断点
gdb_proc.stdin.write(b'b *0x40092f\n')
gdb_proc.stdin.write(b'r '+ program_args + b'\n')
gdb_proc.stdin.flush()

# 等待程序运行并断点处停止
output = gdb_proc.stdout.readline().decode()
while 'Breakpoint 1, ' not in output:
    output = gdb_proc.stdout.readline().decode()

# 在断点处查看寄存器状态
gdb_proc.stdin.write(b'print $rsp\n')
gdb_proc.stdin.flush()

# 读取并保存寄存器状态信息
rsp_register_info = ''
output = gdb_proc.stdout.readline().decode()
while '$1 = (void *) ' not in output:
    output = gdb_proc.stdout.readline().decode()

rsp_register_info = output.split('(void *) ')[-1]

# 关闭 GDB 进程
gdb_proc.stdin.write(b'quit\n')
gdb_proc.stdin.flush()

# return rsp_register_info