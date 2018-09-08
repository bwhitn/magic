from pexpect import popen_spawn


class Radare(object):


    def __init__(self, prog):
        assert isinstance(prog, str)
        self.dbg = popen_spawn.PopenSpawn("radare2 "+prog)
        self.dbg.sendline("ood")
        match = self.dbg.expect(r'\[(0x[a-f0-9]+)\]')
        if match:
            self.current = p.match.group(1).decode("utf-8")
        else:
            raise ValueError("invalid input received on __init__")


    def run_to_program(self):
        pass

    def step_over(self):
        pass

    def step_into(self):
        pass

    def add_break(self, location):
        pass

    def rm_break(self, location):
        pass

    def cont(self):
        pass

    def get_reg(self, reg):
        assert isinstance(reg, str)
        pass

    def list_mem(self):
        pass

    def get_mem(self, from_add, size):
        pass