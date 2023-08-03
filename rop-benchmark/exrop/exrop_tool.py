import sys
from subprocess import Popen, PIPE, STDOUT, TimeoutExpired


class Exrop:

    def __init__(self, binary, input, job, ropchain, bad_chars, check_argv_func_addr = 0, check_reg = 0):
        self.binary = binary
        self.input = input
        self.job = job
        self.logger = job.logger
        self.ropchain = ropchain
        self.bad_chars = bad_chars
        self.check_argv_func_addr = check_argv_func_addr
        self.check_reg = check_reg

    def run(self, timeout):
        from os import environ, pathsep, unlink, symlink
        from os.path import abspath, dirname, join

        pp = "/usr/bin/python3" # environ["PYTHONPATH"]
        # del environ["PYTHONPATH"]
        environ["PYTHONPATH"] = "{}{}{}".format(pp, pathsep, "/exrop")

        runner = abspath(join(dirname(__file__), "exrop_runner.py"))
        cmd = ["/usr/bin/python3", runner, self.binary, self.ropchain]
        if self.bad_chars:
            cmd += [self.bad_chars]
        
        if self.check_argv_func_addr != 0:
            cmd += [str(self.check_argv_func_addr)]
            cmd += [str(self.check_reg)]
        self.logger.debug("RUN exrop run {}".format(" ".join(cmd)))
        # print(cmd)
        process = Popen(cmd, env=environ, stderr=STDOUT, stdout=PIPE)

        environ["PYTHONPATH"] = pp

        try:
            stdout = process.communicate(timeout=timeout)[0]
            self.logger.debug("exrop runner output:")
            self.logger.debug(stdout.decode(errors='ignore'))
        except TimeoutExpired:
            process.kill()
            self.logger.critical("FAIL TIMEOUT")
            exit(3)

        if process.returncode != 0:
            self.logger.error("Compilation ERROR with {} (exrop)".format(process.returncode))
            exit(1)
