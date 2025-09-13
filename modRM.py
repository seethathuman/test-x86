class ModRM:
    def __init__(self, cpu):
        self.rm = None
        self.reg = None
        self.mod = None
        self.byte = None
        self.addr = None
        self.disp = 0
        self.cpu = cpu

    def calc(self, byte):
        self.mod = (byte & 0b11000000) >> 6
        self.reg = (byte & 0b00111000) >> 3
        self.rm  = (byte & 0b00000111)
        self.byte = byte
        self.cpu.ip += 1  # consumed modrm

        if self.cpu.address_size == 2:  # 16-bit addressing (real mode or 0x67 override in pmode)
            self._resolve_real_mode()
        else:  # 32-bit addressing
            self._resolve_protected_mode()

    def __call__(self, *args, **kwargs):
        if args:
            byte = args[0]
        else:
            byte = self.cpu.fetch(1)[0]
        self.calc(byte)
        return self

    def _resolve_real_mode(self):
        reg_pairs = [
            lambda: self.cpu.get_reg(1, 2) + self.cpu.get_reg(6, 2),  # [BX+SI]
            lambda: self.cpu.get_reg(1, 2) + self.cpu.get_reg(7, 2),  # [BX+DI]
            lambda: self.cpu.get_reg(5, 2) + self.cpu.get_reg(6, 2),  # [BP+SI]
            lambda: self.cpu.get_reg(5, 2) + self.cpu.get_reg(7, 2),  # [BP+DI]
            lambda: self.cpu.get_reg(6, 2),                           # [SI]
            lambda: self.cpu.get_reg(7, 2),                           # [DI]
            lambda: self.cpu.get_reg(5, 2),                           # [BP]
            lambda: self.cpu.get_reg(1, 2),                           # [BX]
        ]

        base = 0
        if self.mod == 0b00:  # no displacement (except rm=110 => [disp16])
            if self.rm == 0b110: # disp16
                self.disp = int.from_bytes(self.cpu.fetch(1, 2), 'little')
                base = self.disp
                self.cpu.ip += 2
            else:
                base = reg_pairs[self.rm]()
        elif self.mod == 0b01:  # disp8
            self.disp = int.from_bytes(self.cpu.fetch(1, 1), 'little', signed=True)
            base = reg_pairs[self.rm]() + self.disp
            self.cpu.ip += 1
        elif self.mod == 0b10:  # disp16
            self.disp = int.from_bytes(self.cpu.fetch(1, 2), 'little', signed=True)
            base = reg_pairs[self.rm]() + self.disp
            self.cpu.ip += 2
        elif self.mod == 0b11:  # register direct
            self.addr = None
            return

        # segment selection: if addressing uses BP, use SS, else DS
        if (self.rm in (0b010, 0b011, 0b110)) and not (self.mod == 0 and self.rm == 0b110):
            segment = self.cpu.ss
        else:
            segment = self.cpu.ds

        self.addr = self.cpu.resolve_address(segment, base & 0xFFFF)
        self.cpu.log(f"Resolved ModRM address: {self.addr:x}")

    def _resolve_protected_mode(self):
        index_val = 0

        if self.mod != 0b11 and self.rm == 0b100:  # SIB byte follows
            sib = self.cpu.fetch(1, 1)[0]
            self.cpu.ip += 1
            scale = 1 << ((sib & 0b11000000) >> 6)
            index = (sib & 0b00111000) >> 3
            base_reg = sib & 0b00000111

            if index != 0b100:  # not ESP
                index_val = self.cpu.get_reg(index, 4) * scale

            if base_reg == 0b101 and self.mod == 0b00:
                # disp32 only
                disp = int.from_bytes(self.cpu.fetch(1, 4), 'little', signed=True)
                base = disp
                self.cpu.ip += 4
            else:
                base = self.cpu.get_reg(base_reg, 4)

        else:
            if self.mod == 0b00 and self.rm == 0b101:
                # disp32 only
                base = int.from_bytes(self.cpu.fetch(1, 4), 'little', signed=True)
                self.cpu.ip += 4
            else:
                base = self.cpu.get_reg(self.rm, 4)

        # add displacement
        if self.mod == 0b01:
            self.disp = int.from_bytes(self.cpu.fetch(1, 1), 'little', signed=True)
            base += self.disp
            self.cpu.ip += 1
        elif self.mod == 0b10:
            self.disp = int.from_bytes(self.cpu.fetch(1, 4), 'little', signed=True)
            base += self.disp
            self.cpu.ip += 4

        if self.mod == 0b11:
            self.addr = None
            return

        self.addr = self.cpu.resolve_address(self.cpu.ds, (base + index_val) & 0xFFFFFFFF)

    def is_register(self):
        return self.mod == 0b11

    def read(self, size: int = 0) -> int:
        if not size:
            size = self.cpu.size
        if self.is_register():
            return self.cpu.get_reg(self.rm, size)
        else:
            data = self.cpu.memory.read(self.addr, size)
            return int.from_bytes(data, 'little')

    def write(self, value: int, size: int = 0) -> None:
        if not size:
            size = self.cpu.size
        if self.is_register():
            self.cpu.log(f"ModRM write {value:x} to {self.cpu.reg_name(self.rm, size)}")
            self.cpu.set_reg(self.rm, value, size)
        else:
            self.cpu.log(f"ModRM write {value:x} to {self.addr:x}")
            self.cpu.memory.write(self.addr, value.to_bytes(size, 'little'))
