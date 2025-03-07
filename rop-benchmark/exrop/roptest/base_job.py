#!/usr/bin/python3
# -*- coding: utf-8 -*-
from argparse import ArgumentParser
from os.path import dirname, realpath, exists, splitext
from sys import exit
from subprocess import Popen, PIPE, STDOUT


class BaseJob:

    def __init__(self):
        self.script_file = None
        self.vuln_trigger_data = None
        self.vuln_trigger_data_size = {}
        self.rop_tool = None
        self.script_dir = None
        self.cwd = None
        self.timeout = None
        self.binary = None
        self.ropchain = None
        self.arch = None
        self.vuln = None
        self.input = None
        self.logger = None
        self.vuln_run_output = None
        self.debug = None
        self.info = None
        self.error = None
        self.failure = None
        self.parser = self.create_parser()
        self.bad_chars = ''
        self.fill = 'a'

    @staticmethod
    def determine_arch(binary):
        """Return arch depending from binary architecture, used as key into `vuln_trigger_data_size`."""
        # Note: it should be implemented in LinuxJob and WindowsJob
        return NotImplemented

    @staticmethod
    def find_rw_section(binary, section_name=".data"):
        """Return address of rw memory region."""
        # Note: it should be implemented in LinuxJob and WindowsJob
        return NotImplemented

    def get_func_addr(self, binary, function_name):
        """Return `function_name` function address inside `binary`."""
        # Note: it should be implemented in LinuxJob and WindowsJob
        return NotImplemented

    def run(self):
        """Job processing."""
        # Initialization
        parsed_args = self.parser.parse_args()
        self.initialize_parameters(parsed_args)
        self.create_loggers()
        self.print_parameters()

        if not self.check_only:
            # Job specific action
            self.job_specific()

            # Actual run of tool.
            vuln_binary = self.binary
            if "synthetic" in self.binary:
                self.binary = f"{splitext(self.binary)[0]}.gdt64"
            self.run_rop_tool()
            self.binary = vuln_binary

        if not exists(self.ropchain):
            self.failure("ERROR (not generated)")
            exit(1)

        if self.bad_chars:
            import binascii
            with open(self.ropchain, 'rb') as ropchain_data:
                payload = ropchain_data.read()
            for char in binascii.unhexlify(self.bad_chars):
                if char in payload:
                    self.failure("ERROR (payload contains badchars)")
                    exit(1)

        # Prepare input date for target test binary.
        self.write_input()

        if self.generate_only:
            self.info("GENERATED")
            exit(0)

        # Perform 10 functionality tests.
        stable = True
        for _ in range(10):
            # Run test binary.
            self.run_vuln_binary()

            # Check if exploit correctly works.
            if self.check_functionality():
                stable = False
            else:
                if not stable:
                    self.debug("Unstable functionality tests")
                exit(2)

        self.info("OK")
        exit(0)

    @staticmethod
    def create_parser():
        parser = ArgumentParser(description="Rop-benchmark entry point for one test of one tool")
        parser.add_argument("-s", "--script-dir", type=str,
                            help="Path to script hosted directory")
        parser.add_argument("-t", "--timeout", type=int, default=300,
                            help="The number of seconds for timeout test")
        parser.add_argument("binary", type=str,
                            help="Binary for testing")
        parser.add_argument("-c", "--check-only",
                            action='store_true', default=False,
                            help="Only check chain generated previously")
        parser.add_argument("-g", "--generate-only",
                            action="store_true", default=False,
                            help="Only generate chains")
        parser.add_argument("-d", "--badchars", type=str,
                            help="Bytes banned for use as part of chain")
        parser.add_argument("-l", "--check_reg", type=int,
                            help="check reg count")
        return parser

    @staticmethod
    def get_script_dir(file):
        return dirname(realpath(file))

    def create_loggers(self):
        """Initialize logging. For every test created separate output file of job run."""
        from logging import getLogger, FileHandler, StreamHandler, Formatter
        from logging import DEBUG, INFO
        logger = getLogger("rop-benchmark:{}:{}".format(self.rop_tool, self.binary))
        logger.setLevel(DEBUG)
        fh = FileHandler('{}.{}.output'.format(self.binary, self.rop_tool), mode='w')
        fh.setLevel(DEBUG)
        ch = StreamHandler()
        ch.setLevel(INFO)
        formatter = Formatter('%(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        logger.addHandler(fh)
        logger.addHandler(ch)
        self.logger = logger
        self.debug = self.logger.debug
        self.info = self.logger.info
        self.error = self.logger.error
        self.failure = self.logger.critical

    def initialize_parameters(self, args):
        from os.path import isabs, relpath
        from os import getcwd
        self.check_only = args.check_only
        self.generate_only = args.generate_only
        self.cwd = getcwd()
        if args.script_dir:
            self.script_dir = args.script_dir
        else:
            self.script_dir = self.get_script_dir(self.script_file)
        self.timeout = args.timeout
        self.check_reg = args.check_reg
        self.binary = relpath(args.binary, self.cwd) \
            if isabs(args.binary) else args.binary
        self.arch = self.determine_arch(self.binary)
        self.input = "{}.{}.input".format(self.binary, self.rop_tool)
        self.ropchain = "{}.{}.ropchain".format(self.binary, self.rop_tool)
        if args.badchars:
            self.bad_chars = args.badchars
            import binascii
            if self.fill.encode('ascii') in binascii.unhexlify(self.bad_chars):
                self.fill = None
                for i in range(256):
                    if bytes([i]) not in binascii.unhexlify(self.bad_chars):
                        self.fill = bytes([i]).decode('ascii')
                        break
                if self.fill is None:
                    raise ValueError("No suitable fill character is available")
        self.vuln_trigger_data = self.vuln_trigger_data_size[self.arch] * self.fill


    def print_parameters(self):
        self.debug("Run with parameters:")
        self.debug("rop_tool: '{}'".format(self.rop_tool))
        self.debug("binary: '{}'".format(self.binary))
        self.debug("arch: '{}'".format(self.arch))
        self.debug("script_dir: '{}'".format(self.script_dir))
        self.debug("timeout: '{}'".format(self.timeout))
        self.debug("check only {}".format(self.check_only))
        self.debug("generate only {}".format(self.generate_only))

    def job_specific(self):
        """Do job specific action."""
        # Note: it may be redefined in some jobs.
        pass

    def run_rop_tool(self, extra_opts=None):
        """Run tool for test binary."""
        # Note: it should be implemented in job runner tool/job_{exploit_type}.py.
        return NotImplemented

    def write_input(self, extra_buf=None):
        """Create input file for test binary."""
        with open(self.input, 'wb') as input_data:
            input_data.write(self.vuln_trigger_data.encode('ascii'))
            with open(self.ropchain, 'rb') as ropchain_data:
                input_data.write(ropchain_data.read())
                if extra_buf is not None:
                    input_data.write(extra_buf)

    def run_vuln_binary(self):
        """Run test binary."""
        # run_cmd = ["qemu-mips -L "/usr/mips-linux-gnu" ./{}".format(self.binary), self.input]
    
        # run_cmd = ["./{}".format(self.binary), self.input]
        
        import random
        import string
        import subprocess
        letters = string.ascii_lowercase
        inputFileName = '/tmp/' + ''.join(random.choice(letters) for i in range(6))
        subprocess.run(['cp', self.input, inputFileName], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        inputfilename_bak = self.input
        self.input = inputFileName
        # self.input = inputfilename_bak
        # subprocess.run(['rm', inputFileName], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if(self.check_reg != None and isinstance(self.check_reg, int) and self.check_reg > 0):
            if('MIPS_MSB' in self.arch):
                run_cmd = "qemu-mips -L \"/usr/mips-linux-gnu\" ./{} {} {}".format(self.binary, self.input, self.check_reg)
            elif('MIPS_LSB' in self.arch):
                run_cmd = "qemu-mipsel -L \"/usr/mipsel-linux-gnu\" ./{} {} {}".format(self.binary, self.input, self.check_reg)
            elif('ARM_LSB' in self.arch):
                run_cmd = "qemu-arm -L \"/usr/arm-linux-gnueabihf\" ./{} {} {}".format(self.binary, self.input, self.check_reg)
            else:
                run_cmd = "./{} {} {}".format(self.binary, self.input, self.check_reg)
        elif(self.binary.endswith('gdt64') or self.binary.endswith('vuln64')):
            if('MIPS_MSB' in self.arch):
                run_cmd = "qemu-mips -L \"/usr/mips-linux-gnu\" ./{} {}".format(self.binary, self.input)
            elif('MIPS_LSB' in self.arch):
                run_cmd = "qemu-mipsel -L \"/usr/mipsel-linux-gnu\" ./{} {}".format(self.binary, self.input)
            elif('ARM_LSB' in self.arch):
                run_cmd = "qemu-arm -L \"/usr/arm-linux-gnueabihf\" ./{} {}".format(self.binary, self.input)
            else:
                run_cmd = "./{} {}".format(self.binary, self.input)
        else:
            if('MIPS_MSB' in self.arch):
                run_cmd = "qemu-mips -L \"/usr/mips-linux-gnu\" ./{} {} {}".format(self.binary, self.input, 0)
            elif('MIPS_LSB' in self.arch):
                run_cmd = "qemu-mipsel -L \"/usr/mipsel-linux-gnu\" ./{} {} {}".format(self.binary, self.input, 0)
            elif('ARM_LSB' in self.arch):
                run_cmd = "qemu-arm -L \"/usr/arm-linux-gnueabihf\" ./{} {} {}".format(self.binary, self.input, 0)
            else:
                run_cmd = "./{} {} {}".format(self.binary, self.input, 0)
        self.debug("Run binary: {}".format(" ".join(run_cmd)))
        run = Popen(run_cmd, shell=True, stdout=PIPE, stderr=STDOUT)
        self.vuln_run_output = run.communicate()[0]

        self.input = inputfilename_bak
        subprocess.run(['rm', inputFileName], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def get_vuln_output(self):
        output = self.vuln_run_output.decode(errors='ignore')
        self.debug(output)
        return output.splitlines()

    def check_functionality(self):
        """Check if exploit works."""
        output_lines = self.get_vuln_output()
        # if(self.check_reg != None and isinstance(self.check_reg, int) and self.check_reg > 0):
        #     # check 
        #     check_flag = False
        #     for index, line in enumerate(output_lines):
        #         if(line.startswith('===check write_reg API begin===') and len(output_lines) > index + 1 and output_lines[index + 1].startswith('a1')):
        #             write_reg_result = output_lines[index + 1]
        #             result = [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x66666]
        #             check_flag = True
        #             write_reg_result = write_reg_result.strip().split(', ')
        #             for i in range(self.check_reg):
        #                 # if(i == self.check_reg - 1):
        #                 #     result[i] = 255
        #                 if(not eval(write_reg_result[i].split(' = ')[-1]) == result[i]):
        #                     check_flag = False
        #             break
        #     if(check_flag == False):
        #         return False
        #     else:
        #         return True
        # else:
        stripped_lines = [line.strip() for line in output_lines]
        if "SUCCESS" in stripped_lines:
            if "PARAMETERS ARE CORRECT" in stripped_lines:
                return True
            else:
                self.failure("FAIL PARAMS")
                return False
        else:
            self.failure("FAIL HIJACK")
            return False
