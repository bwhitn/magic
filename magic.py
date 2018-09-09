from pexpect import popen_spawn, TIMEOUT
import json


class Radare(object):


    def __init__(self, prog):
        assert isinstance(prog, str)
        self.dbg = popen_spawn.PopenSpawn("radare2 "+prog)
        self.dbg.sendline("ood")
        self.dbg.sendline("aa")
        match = self.dbg.expect([TIMEOUT , r'.*\[(0x[a-f0-9]+)\]>.*'])
        if match:
            self.current = self.dbg.match.group(1).decode("utf-8")
        else:
            raise ValueError("invalid input received on __init__")

    def _expect(self):
        pass

    def cont(self):
        self.dbg.sendline("dc")

    def add_break(self, location):
        self.dbg.sendline("db "+location)
        self._expect()

    def rm_break(self, location):
        self.dbg.sendline("db -"+location)
        pass

    def get_reg(self, reg):
        assert isinstance(reg, str)
        self.dbg.sendline("dr " + reg)
        #TODO add return registry value
        pass


breakpoints = {}

#debug = Radare("magic")
val = 0
for i in range(0x20, 0x7f):
    curr = 1
    prev = 1
    for x in range(3, i + 1):
        temp = curr
        curr = (prev + curr) & 0xffffffffffffffff
        prev = temp
    print("{}: {}".format(chr(x), hex(curr)))