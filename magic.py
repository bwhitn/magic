from pexpect import popen_spawn, TIMEOUT, spawn


class Radare(object):


    def __init__(self, prog):
        assert isinstance(prog, str)
        self.dbg = spawn("radare2 "+prog)
        self.dbg.sendline("e scr.color = false")
        self.dbg.sendline("e scr.utf8 = false")
        self.dbg.sendline("ood")
        self.dbg.sendline("aa")
        self.breakpoints = set()
        self.breakpoint_map = {}
        match = self.dbg.expect([TIMEOUT, r'.*\[(?:0x[a-f0-9]+)\]>.*'])
        if not match:
            raise ValueError("invalid input received on __init__")

    def cont(self, expectation):
        assert isinstance(expectation, int) or isinstance(expectation, str)
        if isinstance(expectation, str):
            expectation = int(expectation, 16)
        self.dbg.sendline("dc")
        match = self.dbg.expect([TIMEOUT, r'.*\[(0x[a-f0-9]+)\]>.*'])
        while(int(self.get_reg("rip"), 16) != expectation):
            pass
        if match:
            return True
        else:
            return False

    def add_break(self, location):
        self.dbg.sendline("db "+location)
        match = self.dbg.expect([TIMEOUT , r'\s*\[(?:0x[a-f0-9]+)\]>.*'])
        if match == 1 and location not in self.breakpoints:
            point = len(self.breakpoint_map)
            self.breakpoint_map[point] = location
            self.breakpoints.add(location)
            return point
        else:
            return None

    def rm_break(self, index):
        if index in self.breakpoints:
            self.dbg.sendline("db -"+self.breakpoints[index])
            match = self.dbg.expect([TIMEOUT, r'.*\[(?:0x[a-f0-9]+)\]>.*'])
            if match:
                self.breakpoints.remove(self.breakpoint_map[index])
                del self.breakpoint_map[index]
                return True
            else:
                return False
        else:
            return False

    def get_reg(self, reg):
        assert isinstance(reg, str)
        self.dbg.sendline("dr " + reg)
        match = self.dbg.expect([TIMEOUT, r'\s*(0x[0-9a-fA-F]+).*'])
        if match:
            return self.dbg.match.group(1).decode("utf-8")
        else:
            return None
        #TODO add return registry value


def _fibfill():
    retVal = {}
    for i in range(0x20, 0x7f):
        curr = 1
        prev = 1
        for x in range(3, i + 1):
            temp = curr
            curr = (prev + curr) & 0xffffffffffffffff
            prev = temp
        retVal[curr] = chr(x)
    return retVal

fib_map = _fibfill()

debug = Radare("magic")
val = debug.add_break("0x400ad0")
val = debug.cont("0x400ad0")
print(debug.get_reg("rip"))
pass