import sys
import fuckpy3
import logging
from datetime import datetime 
import os
import time
import json
import subprocess
from elftools.elf.elffile import ELFFile

logging.getLogger('angr').setLevel('CRITICAL')
binary = sys.argv[1]
ropchain_path = sys.argv[2]
rw = int(sys.argv[3]) #
arch_type = sys.argv[4]
check_reg_count = 0
check_regs_set_func_addr = 0
if(len(sys.argv) > 5):
    check_regs_set_func_addr = int(sys.argv[5])
if(len(sys.argv) > 6):
    check_reg_count = int(sys.argv[6])

class SGC:

    def __init__(self, binary, ropchain,rw_address, check_regs_set_func_addr = 0, cehck_reg = 0):
        self.rop_tool = "SGC"
        self.binary = binary
        self.binary_input = "{}.SGC.input".format(self.binary)
        self.binary_name = ""
        self.win_stack = ""
        self.ropchain_path = ropchain
        self.rw_address = rw_address
        self.check_regs_set_func_addr = check_regs_set_func_addr
        self.cehck_reg = cehck_reg
        self.reg_lists = ['rax','rbx','rcx','rdx','rsi','rdi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
        self.precondition = {}
        self.twoparams = False # False, True

    def construct_json(self, json_file):
        with open(json_file, 'r') as file:
            # 读取文件内容
            json_data = file.read()

            # 解析 JSON 数据
            data = json.loads(json_data)

            # 处理数据
            # set the binary name
            data['executable'] = self.binary_name

            crash_addr = 0x0
            crash_addr = self.remote_debug_vulret_addr(self.binary)
            print(crash_addr)

            # set the rsp
            preconditions = []
            for reg_info in data['preconditions']:
                if(reg_info[0] == 'RSP'):
                    # rsp_register_info = self.remote_debug(self.binary, crash_addr, pre_reg = 'rsp')
                    rsp_register_info = False
                    if(rsp_register_info != False):
                        reg_info[1] = rsp_register_info
                    else:
                        rsp_register_info = reg_info[1]
                
                if(reg_info[0] == 'IRDst'):
                    if(crash_addr != 0x0):
                        reg_info[1] = crash_addr
                    else:
                        ret_gadget_addr = self.find_ret_gadget(self.binary)
                        if(ret_gadget_addr != 0x0):
                            reg_info[1] = ret_gadget_addr
                
                
                preconditions.append(reg_info)
            
            # get 'rax','rbx','rcx','rdx','rsi','rdi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15' 's precondition

            reg_lists = ['rax','rbx','rcx','rdx','rsi','rdi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
            # for reg_name in reg_lists:
            #     register_info = self.remote_debug(self.binary, crash_addr, pre_reg = reg_name)
            self.remote_debug_all_regs()
            for reg_name in self.precondition:
                register_info = hex(self.precondition[reg_name])
                preconditions.append([reg_name.upper(), register_info, 64])
            print(preconditions)
            data['preconditions'] = preconditions
            # print(preconditions)

            postconditions = []
            for reg_info in data['postconditions']:

                if(reg_info[0] == 'IRDst'):
                    syscall_gadget_addr = self.find_syscall_gadget(self.binary)
                    if(syscall_gadget_addr != ''):
                        reg_info[1] = syscall_gadget_addr
                
                postconditions.append(reg_info)
            
            data['postconditions'] = postconditions

            min_addr, max_addr = self.get_read_mem_range()

            data['read_mem_areas'] = [[hex(min_addr), hex(max_addr)]]
            # print(data['write_mem_areas'][0][0])
            # print(rsp_register_info)
            # print(eval(data['write_mem_areas'][0][0]) > eval(rsp_register_info))
            if(eval(data['write_mem_areas'][0][0]) > eval(rsp_register_info)):
                original_stack_range = data['write_mem_areas'][0]
                data['read_mem_areas'].pop(0)
                data['write_mem_areas'].append([hex(eval(rsp_register_info)), hex(eval(original_stack_range[1]))])
                data['write_mem_areas'].append([hex(min_addr), hex(max_addr)])
            else:
                data['write_mem_areas'].append([hex(min_addr), hex(max_addr)])

            # # 示例：打印数据
            # print(data)
            # print(json_file)
            with open(json_file, 'w') as file:
                json.dump(data, file)
            
        return 

    def remote_debug_all_regs(self):
        # 调试程序的路径和参数
        program_args = self.win_stack

        import random
        import string
        letters = string.ascii_lowercase
        inputFileName = '/tmp/' + ''.join(random.choice(letters) for i in range(6))
        subprocess.run(['cp', self.win_stack, inputFileName], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        program_args = inputFileName

        # from IPython import embed
        # embed()
        # 启动 GDB
        gdb_cmd = ['gdb'] + [self.binary]
        gdb_proc = subprocess.Popen(gdb_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=os.getcwd())

        # 等待 GDB 启动并设置断点
        gdb_proc.stdin.write(b'b vul\n')
        if(self.binary_name.startswith('ex') or self.twoparams):
            gdb_proc.stdin.write(b'r '+ program_args.encode() + b'\n')
        else:
            gdb_proc.stdin.write(b'r '+ program_args.encode() + b' 0 \n')
        # print(program_args.encode())
        gdb_proc.stdin.flush()

        # 等待程序运行并断点处停止
        output = gdb_proc.stdout.readline().decode()
        # print(output)
        while 'Breakpoint 1, vul ' not in output:
            output = gdb_proc.stdout.readline().decode()
            # print(output)

        # 在断点处查看寄存器状态
        gdb_proc.stdin.write(b'disassemble vul\n')
        gdb_proc.stdin.flush()

        # 读取并保存寄存器状态信息
        ret_addr_info = 0x0
        output = gdb_proc.stdout.readline().decode()
        while not output.endswith('ret    \n'):
            output = gdb_proc.stdout.readline().decode()

        ret_addr_info = eval(output.split(' <')[0])
        
        gdb_proc.stdin.write(b'b *'+ hex(ret_addr_info).encode() + b'\n')
        gdb_proc.stdin.write(b'continue\n')
        gdb_proc.stdin.flush()

        # 等待程序运行并断点处停止
        output = gdb_proc.stdout.readline().decode()
        # print(output)
        while 'Breakpoint 2, ' not in output:
            output = gdb_proc.stdout.readline().decode()
            # print(output)

        
        min_addr, max_addr = self.get_read_mem_range()
        for idx, pre_reg in enumerate(self.reg_lists):
            # 在断点处查看寄存器状态
            gdb_proc.stdin.write(b'print $' + pre_reg.encode() + b'\n')
            gdb_proc.stdin.flush()

            # 读取并保存寄存器状态信息
            register_info = ''
            output = gdb_proc.stdout.readline().decode()
            # print(output)
            split_str = '$' + str(idx + 1) + ' = '
            while split_str not in output:
                output = gdb_proc.stdout.readline().decode()
                # print(output)

            if('(void *)' in output):
                output = output.split('(void *) ')[-1]
            else:
                output = output.split(split_str)[-1]
            if('-' in output):
                # 处理值为负数
                register_info = eval(output) & 0xffffffffffffffff
            else:
                register_info = eval(output)
            
            
            # xinfo this value
            gdb_proc.stdin.write(b'xinfo ' + hex(register_info).encode() + b'\n')
            gdb_proc.stdin.flush()

            # 读取并保存寄存器状态信息
            output = gdb_proc.stdout.readline().decode()
            # print(output)
            while 'not mapped' not in output and 'Extended information for virtual address' not in output:
                output = gdb_proc.stdout.readline().decode()

            if('not mapped' in output):
                self.precondition[pre_reg] = register_info
            
            if('Extended information for virtual address' in output):
                if(register_info >= min_addr and register_info <= max_addr):
                    self.precondition[pre_reg] = register_info
        
        print(self.precondition)
        # print(hex(ret_addr_info))
        # 关闭 GDB 进程
        gdb_proc.stdin.write(b'quit\n')
        gdb_proc.stdin.flush()

        subprocess.run(['rm', inputFileName], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # gdb_proc.terminate()
        # time.sleep(2)
        # print("ret_addr_info: " + hex(ret_addr_info))

        # return hex(ret_addr_info)

    def find_ret_gadget(self, program_path):  
        
        ret_gadget_addr = 0x0
        # ROPgadget --binary /ssd/home/rop/rop-benchmark-master/binaries/x86/reallife/vuln/openbsd-65/Xvfb.bin | grep ': ret$'
        # ROPgadget --binary /ssd/home/rop/rop-benchmark-master/binaries/x86/reallife/vuln/openbsd-65/Xvfb.bin | grep ': ret 0$'
        command = ['ROPgadget', '--binary', program_path]
        p1 = subprocess.Popen(command, stdout=subprocess.PIPE)
        process = subprocess.Popen(["grep", ": ret$"], stdin=p1.stdout, stdout=subprocess.PIPE)
        
        # 实时获取输出结果
        for line in process.stdout:
            if(': ret' in line.decode()):
                ret_gadget_addr = line.split(b' : ')[0]
            # print(line.decode())
        
        if(ret_gadget_addr == 0x0):
            command = ['ROPgadget', '--binary', program_path]
            p1 = subprocess.Popen(command, stdout=subprocess.PIPE)
            process = subprocess.Popen(["grep", ": ret 0$"], stdin=p1.stdout, stdout=subprocess.PIPE)
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True)
            # 实时获取输出结果
            for line in process.stdout:
                if(': ret' in line.decode()):
                    ret_gadget_addr = line.split(b' : ')[0]

        return ret_gadget_addr.strip().decode()

    def find_syscall_gadget(self, program_path):

        syscall_gadget_addr = b''
        # ROPgadget --binary /ssd/home/rop/rop-benchmark-master/binaries/x86/reallife/vuln/openbsd-65/Xvfb.bin | grep ': ret$'
        # ROPgadget --binary /ssd/home/rop/rop-benchmark-master/binaries/x86/reallife/vuln/openbsd-65/Xvfb.bin | grep ': ret 0$'
        command = ['ROPgadget', '--binary', program_path]
        p1 = subprocess.Popen(command, stdout=subprocess.PIPE)
        process = subprocess.Popen(["grep", ": syscall$"], stdin=p1.stdout, stdout=subprocess.PIPE)
        # 实时获取输出结果
        for line in process.stdout:
            if(': syscall' in line.decode()):
                syscall_gadget_addr = line.split(b' : ')[0]
            # print(line.decode())
        
        return syscall_gadget_addr.strip().decode()

    def remote_debug(self, program_path, crash_addr, pre_reg = 'rsp'):
        # 调试程序的路径和参数
        # program_path = '/ssd/home/rop/rop-benchmark-master/binaries/x86/reallife/vuln/centos-7.1810/ata_id.bin'
        program_args = self.win_stack
        
        import random
        import string
        letters = string.ascii_lowercase
        inputFileName = '/tmp/' + ''.join(random.choice(letters) for i in range(6))
        subprocess.run(['cp', self.win_stack, inputFileName], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        program_args = inputFileName

        # current_path = os.path.abspath(__file__)
        # gadget_synthesis_dir = os.path.join(current_path, 'gadget_synthesis')
        gadget_synthesis_dir = '/ssd/home/rop/rop-benchmark-master/gadget_synthesis'
        # print(program_path)
        # print(program_args)

        
        # command = program_path + ' ' + program_args + ' &'
        # subprocess.call(command, shell=True)
        # # result = subprocess.Popen(program_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        # command = 'ps -ef|grep ' + program_path +  '|grep -v grep|cut -c 10-16'
        # result = subprocess.run(command, shell=True, capture_output=True, text=True)
        # program_pid = result.stdout


        # print("program_pid = " + program_pid)

        # # from IPython import embed
        # # embed()
        # if(program_pid == '' or len(program_pid.split('\n')) > 2):
        #     command = 'ps -ef|grep ' + program_path
        #     result = subprocess.run(command, shell=True, capture_output=True, text=True)
        #     data = result.stdout
        #     print(data)
        #     return False
        #     # from IPython import embed
        #     # embed()
        # program_pid = program_pid.strip()

        # 启动 GDB
        # gdb_cmd = ['sudo'] + ['gdb'] + ['attach'] +  [program_pid]
        gdb_cmd = ['gdb'] + [program_path]
        gdb_proc = subprocess.Popen(gdb_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=gadget_synthesis_dir)

        # 等待 GDB 启动并设置断点
        gdb_proc.stdin.write(b'b *' + crash_addr.encode() + b'\n')
        # gdb_proc.stdin.write(b'continue\n')
        print(program_args.encode())
        if(self.binary_name.startswith('ex') or self.twoparams):
            gdb_proc.stdin.write(b'r '+ program_args.encode() + b'\n')
        else:
            gdb_proc.stdin.write(b'r '+ program_args.encode() + b'  0 \n')
        gdb_proc.stdin.flush()

        # 等待程序运行并断点处停止
        output = gdb_proc.stdout.readline().decode()
        # print(output)
        while 'Breakpoint 1, ' not in output:
            output = gdb_proc.stdout.readline().decode()
            # print(output)

        # 在断点处查看寄存器状态
        gdb_proc.stdin.write(b'print $' + pre_reg.encode() + b'\n')
        gdb_proc.stdin.flush()

        # 读取并保存寄存器状态信息
        rsp_register_info = ''
        output = gdb_proc.stdout.readline().decode()
        # print(output)
        while '$1 = ' not in output:
            output = gdb_proc.stdout.readline().decode()
            # print(output)

        if('(void *)' in output):
            output = output.split('(void *) ')[-1]
        else:
            output = output.split('$1 = ')[-1]
        if('-' in output):
            # 处理值为负数
            rsp_register_info = eval(output) & 0xffffffffffffffff
        else:
            rsp_register_info = eval(output)

        # 关闭 GDB 进程
        gdb_proc.stdin.write(b'quit\n')
        gdb_proc.stdin.flush()

        subprocess.run(['rm', inputFileName], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # print("rsp_register_info: " + hex(rsp_register_info))
        # from IPython import embed
        # embed()
        return hex(rsp_register_info)

    def remote_debug_vulret_addr(self, program_path, ):
        # 调试程序的路径和参数
        # program_path = '/ssd/home/rop/rop-benchmark-master/binaries/x86/reallife/vuln/centos-7.1810/ata_id.bin'
        program_args = self.win_stack

        import random
        import string
        letters = string.ascii_lowercase
        inputFileName = '/tmp/' + ''.join(random.choice(letters) for i in range(6))
        subprocess.run(['cp', self.win_stack, inputFileName], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        program_args = inputFileName
        # subprocess.run(['rm', inputFileName], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # current_path = os.path.abspath(__file__)
        # gadget_synthesis_dir = os.path.join(current_path, 'gadget_synthesis')
        
        gadget_synthesis_dir = '/ssd/home/rop/rop-benchmark-master/gadget_synthesis'
        # from IPython import embed
        # embed()
        # 启动 GDB
        gdb_cmd = ['gdb'] + [program_path]
        gdb_proc = subprocess.Popen(gdb_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=gadget_synthesis_dir)
        print(program_args.encode())
        # 等待 GDB 启动并设置断点
        gdb_proc.stdin.write(b'b vul\n')
        if(self.binary_name.startswith('ex') or self.twoparams):
            gdb_proc.stdin.write(b'r '+ program_args.encode() + b'\n')
        else:
            gdb_proc.stdin.write(b'r '+ program_args.encode() + b' 0 \n')
        gdb_proc.stdin.flush()

        # 等待程序运行并断点处停止
        output = gdb_proc.stdout.readline().decode()
        while 'Breakpoint 1, vul ' not in output:
            output = gdb_proc.stdout.readline().decode()

        # 在断点处查看寄存器状态
        gdb_proc.stdin.write(b'disassemble vul\n')
        gdb_proc.stdin.flush()

        # 读取并保存寄存器状态信息
        ret_addr_info = 0x0
        output = gdb_proc.stdout.readline().decode()
        while not output.endswith('ret    \n'):
            output = gdb_proc.stdout.readline().decode()

        ret_addr_info = eval(output.split(' <')[0])
        # print(hex(ret_addr_info))
        # 关闭 GDB 进程
        gdb_proc.stdin.write(b'quit\n')
        gdb_proc.stdin.flush()
        subprocess.run(['rm', inputFileName], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # gdb_proc.terminate()
        # time.sleep(2)
        # print("ret_addr_info: " + hex(ret_addr_info))

        return hex(ret_addr_info)

    def run_rop_tool(self):
        
        print("self.binary = " + str(self.binary))
        # current_path = os.path.abspath(__file__)
        gadget_synthesis_dir = '/ssd/home/rop/rop-benchmark-master/gadget_synthesis' # os.path.join(current_path, 'gadget_synthesis')
        target_template_path = '/ssd/home/rop/rop-benchmark-master/gadget_synthesis/targets/target_template' # os.path.join(gadget_synthesis_dir, 'targets', 'target_template')
        # self.binary = '/ssd/home/rop/rop-benchmark-master/binaries/x86/reallife/vuln/centos-7.1810/ata_id.bin'
        # self.binary = '/ssd/home/rop/rop-benchmark-master_binary_bak/binaries_check_args/x86/reallife/vuln/centos-7.1810/ata_id.bin'
        # self.binary = '/ssd/home/rop/rop-benchmark-master/binaries/x86/reallife/vuln/debian-10-cloud/ssh.bin'
        # self.binary = '/ssd/home/rop/rop-benchmark-master/binaries/x86/reallife/vuln/other_dataset_v3/SGC_nginx.bin'
        binary_name = self.binary.split('/')[-1]
        self.binary_name = binary_name

        print("binary_name = " + self.binary_name)
        # 指定目录路径
        dataset_name = self.binary.split('/')[-2]
        
        target_dir =  '/ssd/home/rop/rop-benchmark-master/gadget_synthesis/targets' # os.path.join(gadget_synthesis_dir, 'targets')
        
        dataset_dir = os.path.join(target_dir, dataset_name)

        if not (os.path.exists(dataset_dir) and os.path.isdir(dataset_dir)):
            os.mkdir(dataset_dir)
        # 指定文件路径
        target_file_dir = os.path.join(dataset_dir, binary_name.split('.bin')[0])

        # print("target_file_dir = " + target_file_dir)

        if os.path.exists(target_file_dir) and os.path.isdir(target_file_dir):
            # remove the target dir
            subprocess.run(['rm', '-rf', target_file_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['cp', '-r', target_template_path, target_file_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            # create the target dir
            subprocess.run(['cp', '-r', target_template_path, target_file_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        self.win_stack = os.path.join(target_file_dir, 'stack.bin')

        target_file = os.path.join(target_file_dir, binary_name)
        
        if os.path.exists(target_file):
            pass
        else:
            # copy the target binary
            subprocess.run(['cp', self.binary, target_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # print("target_file = " + target_file)
        self.binary = target_file

        # subprocess.run(['cd', 'gadget_synthesis'])
        # subprocess.call('cd gadget_synthesis', shell=True)

        # construct json file
        json_file = os.path.join(target_file_dir, 'config_execve.json') # config_execve.json  config_mprotect.json
        self.construct_json(json_file)

        target_file_dir = target_file_dir.split('gadget_synthesis/')[-1]
        gadgets_out_dir = os.path.join(target_file_dir, 'gadgets')
        # python3 extractor.py -c config_execve.json targets/pppd -o targets/pppd/gadgets
        # print(gadgets_out_dir)
        gadgets_out_dir = gadgets_out_dir.split('gadget_synthesis/')[-1]
        subprocess.run(['rm', '-rf', gadgets_out_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=gadget_synthesis_dir)
        command_1 = ['python3', 'extractor.py', '-c', 'config_execve.json', target_file_dir, '-o', gadgets_out_dir] # , '-j', '16' # config_execve.json  config_mprotect.json
        # print(command_1)
        process = subprocess.Popen(command_1, stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, cwd=gadget_synthesis_dir)
        # 实时获取输出结果
        for line in process.stdout:
            print(line)

        # # bug line 1    
        # 直接选择使用SGC默认的Gadget集合，而不是使用我们喂给它的一些非对齐的Gadget集合
        # json_file = os.path.join(target_file_dir, '.cache', 'gadgets.json')
        # command_1 = ['python3', 'gen_gadgets.py', target_file, json_file] # , '-j', '16'
        # print(command_1)
        # process = subprocess.Popen(command_1, stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, cwd=gadget_synthesis_dir)
        # # 实时获取输出结果
        # for line in process.stdout:
        #     print(line)
        
        
        # rm -rf targets/pppd/out && python3 synthesizer.py -v -j 16 -c config_execve.json targets/pppd -o targets/pppd/out
        SMT_out_dir = os.path.join(target_file_dir, 'out')
        SMT_out_dir = SMT_out_dir.split('gadget_synthesis/')[-1]
        subprocess.run(['rm', '-rf', SMT_out_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=gadget_synthesis_dir)
        # print(SMT_out_dir)
        command_2 = ['python3', 'synthesizer.py', '-v', '-j', '16', '-c', 'config_execve.json', target_file_dir, '-o', SMT_out_dir] # config_execve.json  config_mprotect.json
        print(command_2)
        process = subprocess.Popen(command_2, stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True, cwd=gadget_synthesis_dir)
        # 实时获取输出结果
        for line in process.stdout:
            print(line)
        print(command_2)
        if(self.get_correct_stack(SMT_out_dir)):
            # print('SGC check itself win')
            # print("check again")
            self.write_csv('result/SGC.3600.x86.0715_3_params_itself.csv',['SGC', self.binary, True])

    def write_csv(self, filename, one_row_data):
        import csv
        with open(filename,'a+') as f:
            csv_write = csv.writer(f)
            csv_write.writerow(one_row_data)

    def get_correct_stack(self, solver_out):

        current_path = os.path.abspath(__file__)
        # gadget_synthesis_dir = os.path.join(current_path, 'gadget_synthesis')
        gadget_synthesis_dir = '/ssd/home/rop/rop-benchmark-master/gadget_synthesis'
        rop_benchmark_dir = '/ssd/home/rop/rop-benchmark-master_argv'
        correct = False
        solver_self_out = os.path.join(gadget_synthesis_dir, solver_out, self.binary_name.split('.bin')[0])
        print("solver_self_out = " + solver_self_out)
        # 获取目录下所有文件夹
        folders = []
        for name in os.listdir(solver_self_out):
            if os.path.isdir(os.path.join(solver_self_out, name)):
                folders.append(name)

        self.ropchain_path = os.path.join(rop_benchmark_dir, self.ropchain_path)
        self.input_path = self.ropchain_path.replace('SGC.ropchain', 'SGC.input')

        subprocess.run(['rm', self.ropchain_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=gadget_synthesis_dir)
        subprocess.run(['rm', self.input_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=gadget_synthesis_dir)
        # 打印文件夹列表
        for folder in folders:
            result_file_path = os.path.join(solver_self_out, folder, 'result.json')
            if(os.path.exists(result_file_path)):
                        
                with open(result_file_path, 'r') as file:
                    # 读取文件内容
                    json_data = file.read()
                    data = json.loads(json_data)

                    # 解析 JSON 数据
                    if('verification' in data and data['verification'] == True):
                        # print(data['verification'])
                        print("it's win")
                        stack_path = os.path.join(solver_self_out, folder, 'stack.bin')
                        # self.add_exp_padding(stack_path)
                        print("[+] maybe win input : " + str(stack_path))
                        correct = True
                        
                        subprocess.run(['cp', stack_path, self.win_stack], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=gadget_synthesis_dir)
                        # subprocess.run(['cp', '-r', stack_path, self.binary_input], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=gadget_synthesis_dir)
                        # self.ropchain_path 
                        # self.ropchain_path = os.path.join(rop_benchmark_dir, self.ropchain_path)
                        print("self.ropchain_path = " + self.ropchain_path)
                        subprocess.run(['cp', stack_path, self.ropchain_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=gadget_synthesis_dir)
                        
                        # from IPython import embed
                        # embed()
                        # self.ropchain = stack_path
                        # input_path = self.binary_input
        
        return correct
        

    def add_exp_padding(self, filename):
        padding_length = 29
        # 打开二进制文件
        with open(filename, 'rb+') as file:
            # 要插入的字符串
            string_to_insert = b'a'*padding_length

            # 定位到起始位置
            file.seek(0)

            # 读取原始数据
            original_data = file.read()

            # 定位到起始位置，并插入字符串
            file.seek(0)
            file.write(string_to_insert)

            # 再写入原始数据
            file.write(original_data)

        # print(f"在文件 '{filename}' 的起始位置插入字符串成功")

    def get_read_mem_range(self,):
        
        '''
        typedef struct {
            Elf32_Word p_type;
            Elf32_Off p_offset;
            Elf32_Addr p_vaddr;
            Elf32_Addr p_paddr;
            Elf32_Word p_filesz;
            Elf32_Word p_memsz;
            Elf32_Word p_flags;
            Elf32_Word p_align;
        }
        '''
        # x = 4; r = 2; w = 1;
        rwx_flag = {0:'', 1:'w', 2:'r', 3 : 'rw', 4:'x', 5: 'xw', 6:'rx', 7:'rwx'} 
        # 要解析的动态库路径

        # 打开 elf 文件
        file = open(self.binary, 'rb')
        # 创建 ELFFile 对象 , 该对象是核心对象
        elf_file = ELFFile(file)

        # 遍历打印 节区头入口
        all_segment = []
        for segment in elf_file.iter_segments():
            all_segment.append(segment)
        
        writable_addr_range = {}
        readable_addr_range = {}
        for segment in all_segment:
            header = segment.header
            sh_flags = header.p_flags
            if(sh_flags in rwx_flag and header.p_vaddr != 0):
                flag_name = rwx_flag[sh_flags]
                if('w' in flag_name):
                    writable_addr_range[header['p_type']] = (header['p_vaddr'], header['p_vaddr'] + header['p_memsz'])
                if('r' in flag_name):
                    readable_addr_range[header['p_type']] = (header['p_vaddr'], header['p_vaddr'] + header['p_memsz'])

        # 遍历打印 节区头入口
        all_section = []
        for section in elf_file.iter_sections():
            all_section.append(section.name)
        for section_name in all_section:
            section = elf_file.get_section_by_name(section_name)
            if(section == None):
                continue
            sh_flags = section.header.sh_flags
            if(sh_flags in rwx_flag and section.header.sh_addr != 0):
                flag_name = rwx_flag[sh_flags]
                if('w' in flag_name):
                    writable_addr_range[section.name] = (section.header.sh_addr, section.header.sh_addr + section.header.sh_size)
                if('r' in flag_name):
                    readable_addr_range[section.name] = (section.header.sh_addr, section.header.sh_addr + section.header.sh_size)
        
        
        if('.bss' in writable_addr_range):
            bss_end_addr = writable_addr_range['.bss'][1]
            bss_end_addr = ((bss_end_addr >> 12) + 1)*0x1000 
            bss_end_addr = writable_addr_range['.bss'][0] + 0x100
            writable_addr_range['.bss'] = (writable_addr_range['.bss'][0], bss_end_addr)
        if('.bss' in readable_addr_range):
            bss_end_addr = readable_addr_range['.bss'][1]
            bss_end_addr = ((bss_end_addr >> 12) + 1)*0x1000 #  不需要这么大的吧
            bss_end_addr = readable_addr_range['.bss'][0] + 0x100
            readable_addr_range['.bss'] = (readable_addr_range['.bss'][0], bss_end_addr)  

        target_addr_range = {'.bss' : writable_addr_range['.bss']}
        # print(writable_addr_range)
        max_addr = 0
        min_addr = 0xffffffffffffffff
        sec_list = list(target_addr_range.keys())
        for sec_name in sec_list:
            if(target_addr_range[sec_name][0] <= min_addr):
                min_addr = target_addr_range[sec_name][0]
            if(max_addr <= target_addr_range[sec_name][1]):
                max_addr = target_addr_range[sec_name][1]
        
        return min_addr, max_addr


mysgc = SGC(binary, ropchain_path, rw, check_regs_set_func_addr = check_regs_set_func_addr, cehck_reg = check_reg_count)

mysgc.run_rop_tool()

