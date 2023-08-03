#!/usr/bin/python3
# -*- coding: utf-8 -*-
from roptest import get_class_name
from exrop_tool import Exrop


job_class = get_class_name()


class RopchainJob(job_class):

    def __init__(self):
        super().__init__()
        self.script_file = __file__
        self.rop_tool = "exrop"

    def run_rop_tool(self):
        if(self.check_reg != None and isinstance(self.check_reg, int) and self.check_reg > 0):
            check_argv_func_addr = self.get_func_addr(self.binary, 'check_argv')
            check_reg = self.check_reg
            rop_tool = Exrop(self.binary, self.input, self, self.ropchain, self.bad_chars, check_argv_func_addr, check_reg = check_reg)
        else:
            rop_tool = Exrop(self.binary, self.input, self, self.ropchain, self.bad_chars)
        rop_tool.run(self.timeout)


RopchainJob().run()
