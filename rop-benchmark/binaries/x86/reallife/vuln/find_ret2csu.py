import os, sys
import capstone
import angr

binary_set = {
    "centos7": "./centos-7.1810",
    "debian10cloud": "./debian-10-cloud",
    "openbsd62": "./openbsd-62",
    "openbsd64": "./openbsd-64",
    "openbsd65": "./openbsd-65",
    "synology": "./synology_geminilake_920",
    "other": "./other_dataset_v3",
    "test": "/ssd/home/rop/rop-benchmark-master_argv/binaries/x86/reallife/orig/debian-10-cloud"
}

valid_binary_count = {
    "centos7": 0,
    "debian10cloud": 0,
    "openbsd62": 0,
    "openbsd64": 0,
    "openbsd65": 0,
    "synology": 0,
    "other": 0,
    "test": 0
}

csu_gadget_bin_pattern = {
    b"\x4c\x89\xf2"+
    b"\x4c\x89\xee"+
    b"\x44\x89\xe7"+
    b"\x41\xff\x14\xdf"+
    b"\x48\x83\xc3\x01"+
    b"\x48\x39\xdd"+
    b"\x75\xea"+
    b"\x48\x83\xc4\x08\x5b\x5d\x41\x5c\x41\x5d\x41\x5e\x41\x5f\xc3", # extra from debian10cloud / centos7
}

csu_func_name = "__libc_csu_init"

# objdump -t bin | grep "\.text" | awk '{print $NF}'

results = {
    "centos7": [],
    "debian10cloud": [],
    "openbsd62": [],
    "openbsd64": [],
    "openbsd65": [],
    "synology": [],
    "other": [],
    "test": []
}

def check(path):
    print(f"Binary: {path}")
    flag_has_csu_symbol = False
    flag_has_csu_gadget = False
    # setp1 find csu symbol
    res = os.popen(f"objdump -t {path} | grep \"\\.text\" | awk '{{print $NF}}'").read().strip().split("\n")
    if csu_func_name in res:
        flag_has_csu_symbol = True
    # step2 find csu gadget
    with open(path, "rb") as f:
        binary = f.read()
        for gadget_pattern in csu_gadget_bin_pattern:
            if binary.find(gadget_pattern) != -1:
                flag_has_csu_gadget = True
    if flag_has_csu_gadget:
        print(f"[*] {path} check result - has csu symbol: {flag_has_csu_symbol}, has csu gadget: {flag_has_csu_gadget}")
        return True

def main():
    for os_type in binary_set:
        binary_path = binary_set[os_type]
        print(f"Checking binary in {os_type}...")
        # 遍历 binary_path
        for root, dirs, files in os.walk(binary_path):
            for file in files:
                if file.endswith(".bin"):
                    valid_binary_count[os_type] += 1
                    bin_path = os.path.join(root, file)
                    if check(bin_path):
                        results[os_type].append(bin_path)

    res_file = open("ret2csu_results.txt", "w")
    print("Results:")
    for os_type in results:
        str = f"\n#### {os_type}: {len(results[os_type])} / {valid_binary_count[os_type]} ####"
        print(str)
        res_file.write(str+"\n")
        for path in results[os_type]:
            print(path)
            res_file.write(path+"\n")


if __name__ == "__main__":             
    main()