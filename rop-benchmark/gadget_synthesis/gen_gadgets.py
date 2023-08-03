from ropper import RopperService
import sys
import logging
import json


logger = logging.getLogger(__name__)
logger.setLevel(level=logging.DEBUG)


class ropper_Gadget_Example():

    def __init__(self, address, lines, bytes, asm_str):
        #super(Gadget, self).__init__()
        self.address = address
        self.lines = lines
        self.bytes = bytes
        self.asm_str = asm_str

    def __str__(self):
        return self.asm_str
    

class Gen_Gadgets():
    def __init__(self, filename, josnfile, arch='x86',is_raw = False, endian = None, load_address= 0, inst_count = 6):
        
        self.rs = RopperService()
        self.arch = arch.lower()
        self.prog_bytes = open(filename,'rb').read()
        
        if self.arch == 'aarch64':
            arch = 'ARM64'
        if is_raw or arch == 'PPC64LE' or arch == 'ARMTHUMB':
            self.rs.addFile(filename,bytes=self.prog_bytes,
            raw=is_raw,arch=arch)
        else: # make ropper set the arch itself
            self.rs.addFile(filename,bytes=self.prog_bytes)
        self.gadgets = []
        
        self.josnfile = josnfile
        self.endian = endian
        self.load_address = load_address
        self.inst_count = inst_count
        self.name = filename
        self.is_raw = is_raw
        

    def load_gadgets(self,):
        '''
        load gadgets using ropper
        '''
        # can't find cache or don't use cache
        # self.rs.options.inst_count = 10
        self.rs.options.inst_count = self.inst_count
        inst_count = self.inst_count 
        self.rs.loadGadgetsFor()
        t = self.rs.getFileFor(name=self.name) # get gadgets from ropper.
        
        if(len(t.gadgets) < 3000):
            inst_count += 2
            self.rs.options.inst_count = inst_count
            self.rs.loadGadgetsFor()
            t = self.rs.getFileFor(name=self.name) # get gadgets from ropper.
        if(len(t.gadgets) > 30000):
            inst_count -= 2
            self.rs.options.inst_count = inst_count
            self.rs.loadGadgetsFor()
            t = self.rs.getFileFor(name=self.name) # get gadgets from ropper.
        while(len(t.gadgets) < 5000):
            inst_count += 1
            if(inst_count > 10):
                break
            self.rs.options.inst_count = inst_count
            self.rs.loadGadgetsFor()
            t = self.rs.getFileFor(name=self.name) # get gadgets from ropper.
        while(len(t.gadgets) > 15000):
            inst_count -= 1
            if(inst_count < 3):
                break
            self.rs.options.inst_count = inst_count
            self.rs.loadGadgetsFor()
            t = self.rs.getFileFor(name=self.name) # get gadgets from ropper.
        if(len(t.gadgets) > 40000):
            self.rs.options.inst_count = inst_count
            self.rs.loadGadgetsFor()
            t = self.rs.getFileFor(name=self.name) # get gadgets from ropper.
        
        # if(len(t.gadgets) > 40000):
        #     self.rs.options.inst_count = 6
        #     self.rs.loadGadgetsFor()
        #     t = self.rs.getFileFor(name=self.name) # get gadgets from ropper.
        if not self.is_raw:
            self.load_address = t.loader.imageBase
            print("[+] load_address = " + str(hex(self.load_address)))
        
        # t.gadgets = []
        logger.info('[inst_count = {0}]: load {1} gadgets(ropper) in {2}'.format(self.rs.options.inst_count, len(t.gadgets),self.name))
        
        ropgadget_gadgets = []
        if(len(t.gadgets) < 15000):
            # 继续添加ROPGadget的内容
            ropper_gadgets_address = []
            for i in t.gadgets:
                ropper_gadgets_address.append(i.address)
                
                # if(i.address == 0x40c76b or i.address == 0x40d19f or i.address == 0x40d1a0 ):
                #     print("debug in check gadget.")
            
            import ropgadget
            import sys
            sys.argv = ['ropgadget', '--dump', '--binary', self.name]
            # if(len(t.gadgets) < 10000):
            #     sys.argv = ['ropgadget', '--all', '--dump', '--binary', self.name]
            # else:
            #     sys.argv = ['ropgadget', '--dump', '--binary', self.name]
            args = ropgadget.args.Args().getArgs()
            core = ropgadget.core.Core(args)
            core.do_binary(self.name)
            core.do_load(0)

            count = 0
            for gadget in core.gadgets():
                if(gadget['vaddr'] in ropper_gadgets_address):
                    count += 1
                    continue
                insns = [ g.strip() for g in gadget['gadget'].split(';') ]
                gadget_asm_str = hex(gadget['vaddr']) + ': ' + gadget['gadget']
                tmp = ropper_Gadget_Example(gadget['vaddr'], insns, gadget['bytes'], gadget_asm_str)
                ropgadget_gadgets.append(tmp)
            print(count)        
        
        # while(len(t.gadgets) + len(ropgadget_gadgets) < 10000):
        #     inst_count += 1
        #     if(inst_count > 10):
        #         break
        #     self.rs.options.inst_count = inst_count
        #     self.rs.loadGadgetsFor()
        #     t = self.rs.getFileFor(name=self.name) # get gadgets from ropper.
        
        for gadget in ropgadget_gadgets:
            t.gadgets.append(gadget)
        self.gadgets = t.gadgets
        print("[+] inst_count = " + str(inst_count))
        logger.info('load {0} gadgets in {1}'.format(len(t.gadgets),self.name))
        # from IPython import embed
        # embed()
        self.save_to_json()
        
    
    def save_to_json(self):
        json_data = []
        for gadget in self.gadgets:
            json_data.append(gadget.address)
            # gadget.address += self.load_address
        # self.josnfile

        with open(self.josnfile, 'w') as file:
            json.dump(json_data, file)
            
# /ssd/home/rop/rop-benchmark-master/gadget_synthesis/targets/centos-7.1810/ata_id_win/.cache/gadgets.json
Gen_Gadgets(filename = sys.argv[1], josnfile = sys.argv[2]).load_gadgets()