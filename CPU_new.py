class CPU:
    def __init__(self, real_mode=True):
        # https://wiki.osdev.org/CPU_Registers_x86
        # Accumulator, Base, Counter, Data, Source, Destination, Stack Pointer, Stack Base Pointer
        # General-purpose registers
        self.eax = self.ebx = self.ecx = self.edx = 0
        self.esi = self.edi = self.ebp = 0
        self.esp = 0x7C00  # Stack pointer initialized to before the boot sector
        self.ip = 0

        # Segment registers
        # Code, Data, Extra, Stack, F, G
        self.cs = self.ds = self.es = self.ss = self.fs = self.gs = 0

        # Flags and control registers
        self.flags = 0
        self.cr0 = self.cr2 = self.cr3 = self.cr4 = self.cr8 = 0
        self.cr1 = self.cr5 = self.cr6 = self.cr7 = None
        self.xcr0 = 0

        # Protected mode descriptor registers
        self.gdtr = self.ldtr = self.idtr = 0

        # System state
        self.memory = None
        self.real_mode = real_mode
        self.operand_override = False

    def execute(self):
        # Fetch prefix bytes first
        prefix = self.fetch()[0]
        if prefix == 0x66 and not self.operand_override:
            self.operand_override = True
            self.ip += 1
            self.execute()
            return

        # Two-byte opcodes start with 0x0F
        if prefix == 0x0F:
            self.match_long()
        else:
            self.match_short()

        self.operand_override = False  # Reset after instruction

    def match_short(self):
        opcode = self.fetch()[0]
        if self.match_extended(opcode): return
        match opcode:

            # NOP (90)
            case 0x90:
                print("NOP")
                self.ip += 1

            # MOV r16/32, imm16/32 = B8+r
            case 0xB8 | 0xB9 | 0xBA | 0xBB | 0xBC | 0xBD | 0xBE | 0xBF:
                reg = opcode - 0xB8 # get register id
                size = self.get_size(2, 4) # get size of operand
                imm = int.from_bytes(self.fetch(1, size), 'little') #
                self.set_reg(reg, imm, size)
                print(f"MOV {self.reg_name(reg, size)}, {hex(imm)}")
                self.ip += 1 + size

            # MOV Sreg, r/m16/32 = 8E /r
            case 0x8E:
                modrm = self.modrm(self.fetch(1, 1)[0])

                mod = modrm[0]  # Addressing mode
                reg = modrm[1]  # Segment register
                rm = modrm[2]  # Source register/memory

                self.ip += 2  # Move past the opcode and modrm byte
                size = self.get_size(2, 4)
                if mod == 0b11:  # Register to register
                    self.set_sreg(reg, self.get_reg(rm, size))
                    print(f"MOV SREG {reg}, {hex(self.get_reg(rm, size))}")
                else:
                    # TODO: Handle memory addressing modes
                    print(f'MOVE operation with {mod} not implemented')
                    exit()

            # LES r16/32, m16:16/32 = C4 /r
            case 0xC4:
                modrm_byte = self.fetch(1, 1)[0]
                mod, reg, rm = self.modrm(modrm_byte)
                size = self.get_size(2, 4)
                disp = 0
                offset = self.ip + 2  # opcode + modrm

                if mod == 0b00:
                    if rm == 0b110 and self.real_mode:
                        # Special case: [disp16] (no base register)
                        disp = int.from_bytes(self.fetch(2, 2), 'little')
                        addr = self.resolve_address(self.ds, disp)
                        self.ip += 4
                    else:
                        addr = self.resolve_address(self.ds, self.get_reg(rm, 2))
                        self.ip += 2
                elif mod == 0b01:
                    disp = int.from_bytes(self.fetch(2, 1), 'little', signed=True)
                    addr = self.resolve_address(self.ds, self.get_reg(rm, 2) + disp)
                    self.ip += 3
                elif mod == 0b10:
                    disp = int.from_bytes(self.fetch(2, 2), 'little', signed=True)
                    addr = self.resolve_address(self.ds, self.get_reg(rm, 2) + disp)
                    self.ip += 4
                else:
                    print("LES does not support register-to-register form (mod 11).")
                    exit()

                # Read offset and segment from memory
                raw = self.memory.read(addr, size + 2)
                offset_val = int.from_bytes(raw[:size], 'little')
                segment_val = int.from_bytes(raw[size:], 'little')

                self.set_reg(reg, offset_val, size)
                self.es = segment_val

                print(f"LES {self.reg_name(reg, size)}, [{hex(addr)}] => {hex(offset_val)}:{hex(segment_val)}")

            # PUSH r16/32 = 50+r
            case 0x50 | 0x51 | 0x52 | 0x53 | 0x54 | 0x55 | 0x56 | 0x57:
                reg = opcode - 0x50 # get register id
                size = self.get_size(2, 4) # get size of operand
                value = self.get_reg(reg, size) # get register value
                self.esp -= size # decrease stack pointer
                addr = self.resolve_address(self.ss, self.esp) # get address for stack pointer
                self.memory.write(addr, value.to_bytes(size, 'little')) # write bytes
                print(f"PUSH {self.reg_name(reg, size)}")
                self.ip += 1

            # POP r16/32 = 58+r
            case 0x58 | 0x59 | 0x5A | 0x5B | 0x5C | 0x5D | 0x5E | 0x5F:
                reg = opcode - 0x58 # get register id
                size = self.get_size(2, 4) # get size of operand
                addr = self.resolve_address(self.ss, self.esp) # get address of stack
                data = self.memory.read(addr, size) # read stack
                value = int.from_bytes(data, 'little')
                self.set_reg(reg, value, size) # set register value
                self.esp += size # increase stack pointer
                print(f"POP {self.reg_name(reg, size)}")
                self.ip += 1

            # JMP rel8 = EB
            case 0xEB:
                offset = self.fetch(1, 1)[0]
                self.ip += offset + 2  # +2 for the opcode and offset byte
                print(f'JMP {hex(offset)}')

            # INT imm8 = CD+r
            case 0xCD:
                code = self.fetch(1, 1)[0]  # fetch interrupt code
                print(f'INT {hex(code)}')
                self.ip += 1
                exit()

            case 0xfa:  # CLI = FA
                self.flags &= ~0x200  # Clear the interrupt flag (IF)
                print("CLI")
                self.ip += 1

            case 0x33:  # XOR r16/32, r/m16/32 = 33+r
                modrm = self.modrm(self.fetch(1, 1)[0])
                mod = modrm[0]
                destreg = modrm[1]
                sourcereg = modrm[2]
                size = self.get_size(2, 4)
                self.ip += 2  # opcode + modrm

                if mod == 0b11:  # Register to register
                    src = self.get_reg(sourcereg, size)
                    dest = self.get_reg(destreg, size)
                    result = src ^ dest
                    self.set_reg(dest, result, size)
                    print(f'XOR {self.reg_name(destreg, size)}, {self.reg_name(sourcereg, size)}')
                else:
                    # TODO: Handle memory addressing modes
                    addr = self.resolve_modrm_address(mod, sourcereg)
                    print(f'XOR operation with mod {bin(mod)} not implemented')
                    exit()
            case _:
                print(f'unknown opcode: {hex(opcode)}')
                self.ip += 1
                exit()

    def match_long(self):
        self.ip += 1
        opcode = self.fetch(0, 1)[0]
        print(f"Unknown Opcode: 0F{hex(opcode)}")
        self.ip += 1

    def set_reg(self, idx, value, size):
        if size == 2:
            self._set_16bit(idx, value)
        else:
            self._set_32bit(idx, value)

    def get_reg(self, idx, size):
        if size == 2:
            return self._get_16bit(idx)
        else:
            return self._get_32bit(idx)

    def set_sreg(self, idx, value):
        if idx == 0: self.cs = value & 0xFFFF
        elif idx == 1: self.ds = value & 0xFFFF
        elif idx == 2: self.es = value & 0xFFFF
        elif idx == 3: self.ss = value & 0xFFFF
        elif idx == 4: self.fs = value & 0xFFFF
        elif idx == 5: self.gs = value & 0xFFFF

    def _set_16bit(self, idx, val):
        if idx == 0: self.eax = (self.eax & 0xFFFF0000) | (val & 0xFFFF)
        elif idx == 1: self.ecx = (self.ecx & 0xFFFF0000) | (val & 0xFFFF)
        elif idx == 2: self.edx = (self.edx & 0xFFFF0000) | (val & 0xFFFF)
        elif idx == 3: self.ebx = (self.ebx & 0xFFFF0000) | (val & 0xFFFF)
        elif idx == 4: self.esp = (self.esp & 0xFFFF0000) | (val & 0xFFFF)
        elif idx == 5: self.ebp = (self.ebp & 0xFFFF0000) | (val & 0xFFFF)
        elif idx == 6: self.esi = (self.esi & 0xFFFF0000) | (val & 0xFFFF)
        elif idx == 7: self.edi = (self.edi & 0xFFFF0000) | (val & 0xFFFF)

    def _set_32bit(self, idx, val):
        match idx:
            case 0: self.eax = val
            case 1: self.ecx = val
            case 2: self.edx = val
            case 3: self.ebx = val
            case 4: self.esp = val
            case 5: self.ebp = val
            case 6: self.esi = val
            case 7: self.edi = val

    def _get_16bit(self, idx):
        match idx:
            case 0: return self.eax & 0xFFFF
            case 1: return self.ecx & 0xFFFF
            case 2: return self.edx & 0xFFFF
            case 3: return self.ebx & 0xFFFF
            case 4: return self.esp & 0xFFFF
            case 5: return self.ebp & 0xFFFF
            case 6: return self.esi & 0xFFFF
            case 7: return self.edi & 0xFFFF

    def _get_32bit(self, idx):
        return [self.eax, self.ecx, self.edx, self.ebx,
                self.esp, self.ebp, self.esi, self.edi][idx]

    @staticmethod
    def reg_name(idx, size=4):
        reg_names = {
            2: ["AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"],
            4: ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
        }
        return reg_names[size][idx]

    def resolve_address(self, segment, offset):
        if self.real_mode:
            return (segment * 16) + offset  # Real mode: segment * 16 + offset
        else:
            # Flat protected mode: segments are ignored unless paging/segmentation is used
            # For now, return just the offset (flat model)
            return offset

    def fetch(self, offset=0, size=1):
        addr = self.resolve_address(self.cs, self.ip + offset)
        return self.memory.read(addr, size)

    @staticmethod
    def modrm(modrm_byte):
        """Returns a tuple of (mod, reg, rm) from the modrm byte."""
        mod = (modrm_byte & 0b11000000) >> 6
        reg = (modrm_byte & 0b00111000) >> 3
        rm = modrm_byte & 0b00000111
        return mod, reg, rm

    def get_size(self, small, big):
        return 2 if self.real_mode or self.operand_override else 4

    def resolve_modrm_address(self, mod, rm):
        size = self.get_size(2, 4)
        base = self.get_reg(rm, size)

        if mod == 0b00:
            return base
        elif mod == 0b01:
            disp = int.from_bytes(self.fetch(0, 1), 'little', signed=True)
            self.ip += 1
            return base + disp
        elif mod == 0b10:
            disp = int.from_bytes(self.fetch(0, 4), 'little', signed=True)
            self.ip += 4
            return base + disp
        else:
            raise Exception("Invalid addressing mode.")

    # Extended common instruction support
    def match_extended(self, opcode):
        # MOV r16/32, r/m16/32 = 8B /r
        if opcode == 0x8B:
            mod, reg, rm = self.modrm(self.fetch(1, 1)[0])
            size = self.get_size(2, 4)
            self.ip += 2
            if mod == 0b11:
                value = self.get_reg(rm, size)
            else:
                addr = self.resolve_modrm_address(mod, rm)
                value = int.from_bytes(self.memory.read(addr, size), 'little')
            self.set_reg(reg, value, size)
            print(f'MOV {self.reg_name(reg, size)}, {"r" + str(rm) if mod == 0b11 else "[" + hex(addr) + "]"}')
            return True

        # MOV r/m16/32, r16/32 = 89 /r
        elif opcode == 0x89:
            mod, rm, reg = self.modrm(self.fetch(1, 1)[0])
            size = self.get_size(2, 4)
            self.ip += 2
            value = self.get_reg(reg, size)
            if mod == 0b11:
                self.set_reg(rm, value, size)
            else:
                addr = self.resolve_modrm_address(mod, rm)
                self.memory.write(addr, value.to_bytes(size, 'little'))
            print(f'MOV {"r" + str(rm) if mod == 0b11 else "[" + hex(addr) + "]"}, {self.reg_name(reg, size)}')
            return True

        # ADD r/m16/32, r16/32 = 01 /r
        elif opcode == 0x01:
            mod, rm, reg = self.modrm(self.fetch(1, 1)[0])
            size = self.get_size(2, 4)
            self.ip += 2
            val2 = self.get_reg(reg, size)
            if mod == 0b11:
                val1 = self.get_reg(rm, size)
                self.set_reg(rm, (val1 + val2) & ((1 << (size * 8)) - 1), size)
            else:
                addr = self.resolve_modrm_address(mod, rm)
                val1 = int.from_bytes(self.memory.read(addr, size), 'little')
                self.memory.write(addr, (val1 + val2).to_bytes(size, 'little'))
            print(f'ADD {self.reg_name(rm, size)}, {self.reg_name(reg, size)}')
            return True

        # INC r16/32 = 40 + r
        elif 0x40 <= opcode <= 0x47:
            reg = opcode - 0x40
            size = self.get_size(2, 4)
            value = (self.get_reg(reg, size) + 1) & ((1 << (size * 8)) - 1)
            self.set_reg(reg, value, size)
            self.ip += 1
            print(f'INC {self.reg_name(reg, size)}')
            return True

        # DEC r16/32 = 48 + r
        elif 0x48 <= opcode <= 0x4F:
            reg = opcode - 0x48
            size = self.get_size(2, 4)
            value = (self.get_reg(reg, size) - 1) & ((1 << (size * 8)) - 1)
            self.set_reg(reg, value, size)
            self.ip += 1
            print(f'DEC {self.reg_name(reg, size)}')
            return True

        # CALL rel16/32 = E8
        elif opcode == 0xE8:
            size = self.get_size(2, 4)
            rel = int.from_bytes(self.fetch(1, size), 'little', signed=True)
            self.ip += 1 + size
            self.esp -= size
            addr = self.resolve_address(self.ss, self.esp)
            self.memory.write(addr, self.ip.to_bytes(size, 'little'))
            self.ip += rel
            print(f'CALL {hex(self.ip)}')
            return True

        # RET = C3
        elif opcode == 0xC3:
            size = self.get_size(2, 4)
            addr = self.resolve_address(self.ss, self.esp)
            value = int.from_bytes(self.memory.read(addr, size), 'little')
            self.esp += size
            self.ip = value
            print(f'RET to {hex(self.ip)}')
            return True

        # HLT = F4
        elif opcode == 0xF4:
            print('HLT')
            exit()

        return False