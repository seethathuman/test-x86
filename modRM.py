class ModRM:
    def __init__(self, cpu, byte=None):
        self.cpu = cpu
        self.size = cpu.get_size()  # 2 or 4
        self.addr = None
        self.disp = 0

        # Fetch ModR/M byte
        if byte is None:
            byte = self.cpu.fetch(1)[0]
        self.byte = byte
        self.mod = (byte & 0b11000000) >> 6
        self.reg = (byte & 0b00111000) >> 3
        self.rm = byte & 0b00000111
        self.cpu.ip += 1 # skip modrm byte

        # Handle 16-bit real mode separately
        if self.cpu.real_mode:
            self._resolve_real_mode()
        else:
            self._resolve_protected_mode()

    def _resolve_real_mode(self):
        # 16-bit addressing using legacy rules
        reg_pairs = [
            lambda: self.cpu.bx + self.cpu.si,
            lambda: self.cpu.bx + self.cpu.di,
            lambda: self.cpu.bp + self.cpu.si,
            lambda: self.cpu.bp + self.cpu.di,
            lambda: self.cpu.si,
            lambda: self.cpu.di,
            lambda: self.disp,
            lambda: self.cpu.bx
        ]

        base = 0
        if self.mod == 0b00:
            if self.rm == 0b110:
                self.disp = int.from_bytes(self.cpu.fetch(1, 2), 'little')
                self.cpu.ip += 2
                base = self.disp
            else:
                base = reg_pairs[self.rm]()
        elif self.mod == 0b01:
            self.disp = int.from_bytes(self.cpu.fetch(1, 1), 'little', signed=True)
            self.cpu.ip += 1
            base = reg_pairs[self.rm]() + self.disp
        elif self.mod == 0b10:
            self.disp = int.from_bytes(self.cpu.fetch(1, 2), 'little', signed=True)
            self.cpu.ip += 2
            base = reg_pairs[self.rm]() + self.disp
        elif self.mod == 0b11:
            self.addr = None
            return

        segment = self.cpu.ds if self.rm != 0b110 else self.cpu.ss
        self.addr = self.cpu.resolve_address(segment, base)

    def _resolve_protected_mode(self):
        # 32-bit addressing with SIB support
        if self.mod != 0b11 and self.rm == 0b100:
            # SIB byte follows
            sib = self.cpu.fetch(1)[0]
            self.cpu.ip += 1

            scale = 1 << ((sib & 0b11000000) >> 6)
            index = (sib & 0b00111000) >> 3
            base = sib & 0b00000111

            base_val = 0
            index_val = 0

            if base == 5 and self.mod == 0b00:
                # disp32 addressing mode: no base
                base_val = int.from_bytes(self.cpu.fetch(1, 4), 'little')
                self.cpu.ip += 4
            else:
                base_val = self.cpu.get_reg(base, 4)

            if index != 4:
                index_val = self.cpu.get_reg(index, 4) * scale

            effective_addr = base_val + index_val

            if self.mod == 0b01:
                disp = int.from_bytes(self.cpu.fetch(1, 1), 'little', signed=True)
                self.cpu.ip += 1
                effective_addr += disp
            elif self.mod == 0b10:
                disp = int.from_bytes(self.cpu.fetch(1, 4), 'little', signed=True)
                self.cpu.ip += 4
                effective_addr += disp

            self.addr = self.cpu.resolve_address(self.cpu.ds, effective_addr)
        elif self.mod == 0b00:
            if self.rm == 0b101:
                # disp32
                self.disp = int.from_bytes(self.cpu.fetch(1, 4), 'little')
                self.cpu.ip += 4
                self.addr = self.cpu.resolve_address(self.cpu.ds, self.disp)
            else:
                base = self.cpu.get_reg(self.rm, 4)
                self.addr = self.cpu.resolve_address(self.cpu.ds, base)
        elif self.mod == 0b01:
            disp = int.from_bytes(self.cpu.fetch(1, 1), 'little', signed=True)
            self.cpu.ip += 1
            base = self.cpu.get_reg(self.rm, 4)
            self.addr = self.cpu.resolve_address(self.cpu.ds, base + disp)
        elif self.mod == 0b10:
            disp = int.from_bytes(self.cpu.fetch(1, 4), 'little', signed=True)
            self.cpu.ip += 4
            base = self.cpu.get_reg(self.rm, 4)
            self.addr = self.cpu.resolve_address(self.cpu.ds, base + disp)
        elif self.mod == 0b11:
            self.addr = None

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
