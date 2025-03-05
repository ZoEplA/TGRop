# How To Run ?

1. Compile the fh.c program and place the generated fh executable into the /bin/fh directory. (This procedure verifies ROP chain execution success in rop-benchmark scenarios, where successful invocation of this program (/bin/fh) during exploitation indicates a perfected ROP chain.)
2. Install dependency environments for each ROP tool within the framework. (Note that configuring dependencies for exrop may require additional time.)
3. Execute run.py to designate ROP tools and sequentially construct ROP chains for target binaries in the binaries directory, following rop-benchmark operational protocols. (A detailed solution is appended to this workflow.)


# Some example of `run.py`

In rop-benchmark, we have implemented several custom modifications:

**Parameter `-t`** specifies the tool name, **`-n`** sets the number of threads, **`-a`** defines the target architecture (determining which subdirectory under `binaries` to use), and **`-s`** indicates using synthetic programs.
```
python3 run.py -t angrop -n 8 -a x86 -s
```

Parameter -r selects a specific test suite (corresponding to directory names under binaries/x86/reallife/vuln), while --timeout sets the maximum execution time per program (in seconds).
```
python3 run.py -t angrop -n 8 -a x86 -r realcve --timeout 3600
```

We introduced the -b parameter to enable single-program testing:
```
python3 run.py -t angrop -n 8 -a x86 -b openbsd-62/sshd.bin
```

We added the `--check_reg` parameter to test the ROP chain that the ROP tool generates to configure parameter registers for the target program. (How is it implemented? Check the modifications under `binaries/x86/reallife/source`.) 
The usage is: `--check_reg 3`, which means searching for a ROP chain that can set the first three parameter registers to arbitrary values and call any function.

```
python3 run.py -t angrop -n 8 -a x86 -r realcve --check_reg 3 --timeout 3600
```


# How to Add a New Dataset
1. Put the dataset folder into both `binaries/x86/reallife/orig` and `binaries/x86/reallife/vuln` (if you are dealing with the x86 architecture).
2. Compile based on the corresponding `binaries/x86/reallife/Makefile`. (If you need to add new ROP targets, you can try modifying the `vul.c` code under the `source` directory and then compile both Makefiles in these two directories.)

# Some Tips

1. The Python environment settings can be crucial. Paying attention to the actual calls in the `*_tool.py` scripts (such as `angrop_tool.py`) can improve efficiency.
2. While `run.py` can generate ROP for many programs, **rop-benchmark** essentially runs scripts like the following to generate ROP chains:
```
python3 /xxxxxx/TGRop/rop-benchmark/angrop/angrop_runner.py binaries/x86/reallife/vuln/realcve/SGC_dnsmasq_binary.bin binaries/x86/reallife/vuln/realcve/SGC_dnsmasq_binary.bin.angrop.ropchain 4199217 3
```

3. If you want this framework to have more functionalities, check out `run.py` and the three key scripts in each tool directory (`angrop_runner.py`, `angrop_tool.py`, `job_execve.pt`) as well as the specific implementations in `roptest`.



# Reference

- rop-benchmark: [https://github.com/ispras/rop-benchmark](https://github.com/ispras/rop-benchmark)
