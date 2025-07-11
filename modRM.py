class ModRM:
    def __init__(self, cpu, byte=None):
        self.cpu = cpu
        if byte is None:
            byte = self.cpu.fetch(1)[0]
        self.byte = byte
        self.mod = (byte & 0b11000000) >> 6
        self.reg = (byte & 0b00111000) >> 3
        self.rm = byte & 0b00000111
        self.disp = 0
        self.size = cpu.get_size()
        self.addr = None

        # Decode displacement if memory addressing
        if self.mod == 0b00:
            if self.rm == 0b110 and self.cpu.real_mode:
                # Special case for 16-bit [disp16]
                self.disp = int.from_bytes(self.cpu.fetch(2, 2), 'little')
                self.addr = self.cpu.resolve_address(self.cpu.ds, self.disp)
                self.cpu.ip += 3 # 1 for the modRM byte, 2 for disp16
            else:
                base = self.cpu.get_reg(self.rm, 2)
                self.addr = self.cpu.resolve_address(self.cpu.ds, base)
                self.cpu.ip += 1  # 1 for the modRM byte
        elif self.mod == 0b01:
            self.disp = int.from_bytes(self.cpu.fetch(1, 1), 'little', signed=True)
            base = self.cpu.get_reg(self.rm, 2)
            self.addr = self.cpu.resolve_address(self.cpu.ds, base + self.disp)
            self.cpu.ip += 1
        elif self.mod == 0b10:
            self.disp = int.from_bytes(self.cpu.fetch(1, 2), 'little', signed=True)
            base = self.cpu.get_reg(self.rm, 2)
            self.addr = self.cpu.resolve_address(self.cpu.ds, base + self.disp)
            self.cpu.ip += 2
        elif self.mod == 0b11:
            self.cpu.ip += 1 # 1 for the modRM byte
            self.addr = None  # Direct register

    def is_register(self):
        return self.mod == 0b11

    def get_operand(self):
        if self.is_register():
            return self.cpu.get_reg(self.rm, self.size)
        else:
            data = self.cpu.memory.read(self.addr, self.size)
            return int.from_bytes(data, 'little')

    def set_operand(self, value):
        if self.is_register():
            self.cpu.set_reg(self.rm, value, self.size)
        else:
            self.cpu.memory.write(self.addr, value.to_bytes(self.size, 'little'))