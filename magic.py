from pexpect import popen_spawn, TIMEOUT
import time

class Radare:


    def __init__(self, prog):
        assert isinstance(prog, str)
        self.dbg = popen_spawn.PopenSpawn("radare2 "+prog)
        self.dbg.sendline("e scr.color = false")
        self.dbg.sendline("e scr.utf8 = false")
        self.dbg.sendline("ood")
        self.dbg.sendline("aa")
        self.breakpoints = set()
        self.breakpoint_map = {}
        match = self.dbg.expect([TIMEOUT, r'.*\[(?:0x[a-f0-9]+)\]>.*'])
        if not match:
            raise ValueError("invalid input received on __init__")

    def cont(self):
        c_rip = self.get_reg("rip")
        self.dbg.sendline("dc")
        match = self.dbg.expect([TIMEOUT, r'.*\[(?:0x[a-f0-9]+)\]>.*'])
        # next function could give incorrect info. Need to wait for the prog to move before moving forward
        while(match and self.get_reg("rip") == c_rip):
            time.sleep(0.1)
        if match:
            return True
        else:
            return False

    def step(self, cnt):
        self.dbg.sendline("ds "+cnt)
        match = self.dbg.expect([TIMEOUT, r'.*\[(?:0x[a-f0-9]+)\]>.*'])
        if match:
            return True
        else:
            return False

    def add_break(self, location):
        assert isinstance(location, str) or isinstance(location, int)
        if isinstance(location, str):
            location = int(location, 16)
        location = hex(location)
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
            return int(self.dbg.match.group(1).decode("utf-8"), 16)
        else:
            return None

    def ana_func(self, addr):
        assert isinstance(addr, str) or isinstance(addr, int)
        if isinstance(addr, str):
            addr = int(addr)
        addr = hex(addr)
        self.dbg.sendline("afr "+addr)
        match = self.dbg.expect([TIMEOUT, r'.*\[(?:0x[a-f0-9]+)\]>.*'])
        if match:
            return True
        else:
            return False


class Answers:

    def __init__(self):
        self.values = []
        self._current = {}

    def add_char(self, char, pos):
        self._current[pos] = char

    def add_chars(self, chars, pos):
        for char in chars:
            self._current[pos] = char
            pos += 1

    def finalize(self):
        val = []
        for key in sorted(self._current.keys()):
            val.append(self._current[key])
        self.values.append(''.join(val))
        self._current = {}

    def get_current(self):
        val = []
        keys = sorted(self._current)
        for i in range(0,80):
            if i in self._current:
                val.append(self._current[i])
            else:
                val.append('A')
        return ''.join(val)

def _fibfill():
    retVal = {}
    for i in range(0x20, 0x7f):
        curr = 1
        prev = 1
        for x in range(2, i+1):
            temp = curr
            curr = (prev + curr) & 0xffffffffffffffff
            prev = temp
        retVal[curr] = chr(x)
    return retVal

fib_map = _fibfill()

ans = Answers()
debug = Radare("magic")

def fib_function(size, offset):
    itr = 0
    while (itr < size):
        loc = debug.get_reg("rip")
        if loc == 0x400c85 or loc == 0x401e4d:
            ans.add_char(fib_map[debug.get_reg("rax")], offset + itr)
            itr += 1
        elif loc == 0x402f08:
            return
        else:
            debug.cont()



func_map = {0x400c55:fib_function, 0x401e1d:fib_function}

for key in sorted(fib_map.keys()):
    print(hex(key)+" "+fib_map[key])

#debug.ana_func(0x400c55)
#debug.ana_func(0x401e1d)
b_call_brk = debug.add_break(0x402efd)
a_call_brk = debug.add_break(0x402f08)
fiba_brk = debug.add_break(0x400c85)
fibb_brk = debug.add_break(0x401e4d)
debug.cont()
while True:
    if debug.get_reg("rip") == 0x402efd:
        func_map[debug.get_reg("rcx")](debug.get_reg("rsi"), debug.get_reg("rdx"))
        #debug.get_reg("rdx") #characters to skip from beginning
        #debug.get_reg("rsi") #length to check
        #debug.get_reg("rcx") #function to call
    else:
        debug.cont()

#0x00401e4d

#print(debug.get_reg("rip"))
pass