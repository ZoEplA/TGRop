#!/usr/bin/python3
# -*- coding: utf-8 -*-
from roptest import get_class_name
from SGC_tool import SGC
import os
import time
import json
import subprocess
from elftools.elf.elffile import ELFFile

job_class = get_class_name()


class RopchainJob(job_class):

    def __init__(self):
        super().__init__()
        self.script_file = __file__
        self.rop_tool = "SGC"
        self.binary_name = ""
        self.win_stack = ""


    def run_rop_tool(self):
        
        binary_name = self.binary.split('/')[-1]
        self.binary_name = binary_name
        if(binary_name.endswith('.gdt64')):
            self.binary_name = binary_name.split('.')[0] + '.vuln64'
            self.binary = self.binary.replace('.gdt64', '.vuln64')

        rw_address = self.find_rw_section(self.binary)
        
        rop_tool = SGC(self.binary, self.input, self, self.ropchain, rw_address, self.bad_chars)
        rop_tool.run(self.timeout)


RopchainJob().run()

# RopchainJob().run_rop_tool()