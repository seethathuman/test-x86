from modRM import ModRM as modRM
from MEM import AddressSpace
class CPU:
    def __init__(self, real_mode=True, debug_mode=False):
        # https://wiki.osdev.org/CPU_Registers_x86
        # Accumulator, Base, Counter, Data, Source, Destination, Stack Pointer, Stack Base Pointer
        # General-purpose registers
        self.eax = self.ebx = self.ecx = self.edx = 0
        self.esi = self.edi = self.ebp = 0
        self.esp = 0x7C00  # Stack pointer initialized to before the boot sector
        self.ip = 0xFFF0

        # Segment registers
        # Code, Data, Extra, Stack, F, G
        self.cs = self.ds = 0xF000
        self.es = self.ss = self.fs = self.gs = 0

        #Bit	Name	Meaning
        #0	    CF	    Carry Flag (unsigned overflow)
        #1	    1	    Reserved (always 1 in EFLAGS)
        #2	    PF	    Parity Flag (low byte has even parity)
        #3	    0	    Reserved (always 0)
        #4	    AF	    Auxiliary Carry (BCD operations)
        #5	    0	    Reserved (always 0)
        #6	    ZF	    Zero Flag (result is zero)
        #7	    SF	    Sign Flag (result is negative)
        #8	    TF	    Trap Flag (single-step debug mode)
        #9	    IF	    Interrupt Enable Flag
        #10	    DF	    Direction Flag (string ops direction)
        #11	    OF	    Overflow Flag (signed overflow)
        #12	    IOPL	I/O Privilege Level (bit 0)
        #13	    IOPL	I/O Privilege Level (bit 1)
        #14	    NT	    Nested Task Flag
        #15	    0	    Reserved (always 0)
        #16	    RF	    Resume Flag (used with debug exceptions)
        #17	    VM	    Virtual-8086 Mode
        #18	    AC	    Alignment Check
        #19	    VIF	    Virtual Interrupt Flag (virtual IF)
        #20	    VIP	    Virtual Interrupt Pending
        #21	    ID	    ID Flag (can CPUID instruction be used?)
        #22–31	0	    Reserved (always 0)

        # Flags and control registers
        self.flags = 0b01000000000000000000000000000000
        self.cr0 = self.cr2 = self.cr3 = self.cr4 = self.cr8 = 0
        self.cr1 = self.cr5 = self.cr6 = self.cr7 = None
        self.xcr0 = 0

        # Protected mode descriptor registers
        self.gdtr = self.ldtr = self.idtr = 0

        # System state
        self.memory: AddressSpace = AddressSpace()
        self.screen = None
        self.debug_val = 0
        self.debug_mode = debug_mode

        # CPU state
        self.real_mode = real_mode
        self.cursor_x = 0
        self.cursor_y = 0

        # Overides
        self.overide_count = 0
        self.segment_override = None
        self.operand_override = False


    def execute(self):
        # Fetch prefix bytes first
        prefix = self.fetch()[0]
        if self.overide_count < 4:
            if prefix == 0x66:
                self.operand_override = True
                self.ip += 1
                self.overide_count += 1
                self.execute()
                return
            if prefix == 0x36:
                self.segment_override = self.ss
                self.ip += 1
                self.overide_count += 1
                self.execute()
                return

        # Two-byte opcodes start with 0x0F
        if prefix == 0x0F:
            self.match_long()
        else:
            self.match_short()

        self.operand_override = False  # Reset after instruction
        self.segment_override = None
        self.overide_count = 0

    def match_short(self):
        opcode = self.fetch()[0]

        match opcode:
            # HLT = F4
            case 0xF4:
                self.halt("HALT INSTRUCTION")
                self.ip += 1

            # NOP = 90
            case 0x90:
                self.log("NOP")
                self.ip += 1

            # MOV r/m16/32, r16/32 = 89 /r
            case 0x89:
                modrm = modRM(self)
                size = self.get_size()
                value = self.get_reg(modrm.reg, size)
                if modrm.mod == 0b11: # register to register
                    self.set_reg(modrm.rm, value, size)
                    self.log(f"MOV {self.reg_name(modrm.rm, size)}, {hex(value)}")
                else:
                    self.memory.write(modrm.addr, value)
                    self.log(f"MOV {hex(modrm.addr)}, {hex(value)}")
                self.ip += 1

            # MOV r/m16/32, imm16/32 = C7 /0 imm
            case 0xC7:
                size = self.get_size()
                modrm = modRM(self)
                value = self.fetch(1, size)
                if modrm.reg:
                    self.halt("REG is non-0 while executing /0 instruction")
                if modrm.mod == 0b11: # register direct
                    self.set_reg(modrm.rm, value, size)
                    self.log(f"MOV {self.reg_name(modrm.rm, size)} {hex(int.from_bytes(value, 'little'))}")
                else: # direct memory addressing
                    self.memory.write(modrm.addr, value)
                    self.log(f"MOV {hex(modrm.addr)} {hex(int.from_bytes(value, 'little'))}")
                self.ip += 1 + size

            # MOV r16/32, imm16/32 = B8+r
            case 0xB8 | 0xB9 | 0xBA | 0xBB | 0xBC | 0xBD | 0xBE | 0xBF:
                reg = opcode - 0xB8 # get register id
                size = self.get_size() # get size of operand
                imm = int.from_bytes(self.fetch(1, size), 'little')
                self.set_reg(reg, imm, size)
                self.log(f"MOV {self.reg_name(reg, size)}, {hex(imm)}")
                self.ip += 1 + size

            # MOV r8, imm8 = B0+r
            case 0xB0 | 0xB1 | 0xB2 | 0xB3 | 0xB4 | 0xB5 | 0xB6 | 0xB7:
                reg = opcode - 0xB0  # get register id
                imm = int.from_bytes(self.fetch(1, 1), 'little')
                self.set_reg(reg, imm, 1)
                self.log(f"MOV r8 {self.reg_name(reg, 1)}, {hex(imm)}")
                self.ip += 2

            # MOV Sreg, r/m16/32 = 8E /r
            case 0x8E:
                modrm = modRM(self)

                mod = modrm.mod  # Addressing mode
                reg = modrm.reg  # Segment register
                rm = modrm.rm  # Source register/memory

                size = self.get_size()
                if mod == 0b11:  # Register to register
                    self.set_sreg(reg, self.get_reg(rm, size))
                    self.log(f"MOV {self.sreg_name(reg)}, {hex(self.get_reg(rm, 2))}")
                else:
                   self.set_sreg(reg, self.memory.read(modrm.addr, 2))
                self.ip += 1

            # LES r16/32, m16:16/32 = C4 /r
            case 0xC4:
                modrm_byte = modRM(self)
                addr = modrm_byte.addr
                size = self.get_size()
                reg = modrm_byte.reg  # Register to load into

                # Read offset and segment from memory
                raw = self.memory.read(addr, size + 2)
                offset_val = int.from_bytes(raw[:size], 'little')
                segment_val = int.from_bytes(raw[size:], 'little')

                self.set_reg(reg, offset_val, size)
                self.es = segment_val

                self.log(f"LES {self.reg_name(reg, size)}, [{hex(addr)}] => {hex(offset_val)}:{hex(segment_val)}")
                self.ip += 1

            # PUSH r16/32 = 50+r
            case 0x50 | 0x51 | 0x52 | 0x53 | 0x54 | 0x55 | 0x56 | 0x57:
                reg = opcode - 0x50 # get register id
                size = self.get_size() # get size of operand
                value = self.get_reg(reg, size) # get register value
                self.esp -= size # decrease stack pointer
                addr = self.resolve_address(self.ss, self.esp, False) # get address for stack pointer
                self.memory.write(addr, value.to_bytes(size, 'little')) # write bytes
                self.log(f"PUSH {self.reg_name(reg, size)}")
                self.ip += 1

            # POP r16/32 = 58+r
            case 0x58 | 0x59 | 0x5A | 0x5B | 0x5C | 0x5D | 0x5E | 0x5F:
                reg = opcode - 0x58 # get register id
                size = self.get_size() # get size of operand
                addr = self.resolve_address(self.ss, self.esp, False) # get address of stack
                data = self.memory.read(addr, size) # read stack
                value = int.from_bytes(data, 'little')
                self.set_reg(reg, value, size) # set register value
                self.esp += size # increase stack pointer
                self.log(f"POP {self.reg_name(reg, size)}")
                self.ip += 1

            # LODSB = AC
            case 0xAC:
                addr = self.resolve_address(self.ds, self.esi)  # Address in DS:ESI
                byte = self.memory.read(addr, 1)[0]
                self.set_reg(0, byte, 1)  # Load byte into AL
                self.esi += (self.get_flag(10) * -2) + 1 # get direction flag (DF) (1 = -1, 0 = +1)
                self.ip += 1
                self.log(f'LODSB => AL = {hex(byte)}, ESI = {hex(self.esi)}, resolved address = {hex(addr)}')

            # CMP AL, imm8 = 3C ib
            case 0x3C:
                src = self.fetch(1, 1)[0]  # fetch immediate byte
                dest = self.get_reg(0, 1)  # AL register
                result = dest - src  # perform subtraction
                self.set_flag(0, src > dest) # Set the carry flag (CF) if AL < imm8
                self.set_flag(2, bin(result).count('1') % 2 == 0) # Set the parity flag (PF) if result has even ammount of ones
                self.set_flag(6, result == 0) # Set the zero flag (ZF) if result is zero
                self.set_flag(7, (result & 0x80) != 0)  # Set the sign flag (SF) if result is negative
                self.ip += 2
                self.log(f'CMP AL, {hex(src)}')

            # CMP AX, imm16 = 3D ib
            case 0x3D:
                src = int.from_bytes(self.fetch(1, 2), byteorder="little", signed=True) # fetch immediate byte
                dest = self.get_reg(0, 2)  # AX register
                result = dest - src  # perform subtraction
                self.set_flag(0, src > dest)  # Set the carry flag (CF) if AL < imm8
                self.set_flag(2, bin(result).count(
                    '1') % 2 == 0)  # Set the parity flag (PF) if result has even ammount of ones
                self.set_flag(6, result == 0)  # Set the zero flag (ZF) if result is zero
                self.set_flag(7, (result & 0x80) != 0)  # Set the sign flag (SF) if result is negative
                self.ip += 3
                self.log(f'CMP AX, {hex(src)}')

            # SUB, ADD, OR, ADC, SBB, AND, SUB, XOR, CMP r/m16/32, imm8 = 83 /r
            case 0x83:
                modrm = modRM(self)
                value = int.from_bytes(self.fetch(1, 1), signed=True)
                mode = modrm.reg
                if modrm.mod == 0b11: # register direct
                    src = self.get_reg(modrm.rm, self.get_size)
                else:
                    src = int.from_bytes(self.memory.read(modrm.addr, self.get_size()), "little", signed=True)
                match mode:
                    case 0b000: # add
                        self.halt("add for 0x83 not supported")
                    case 0b001: # or
                        self.log(f"OR {hex(src)} {hex(value)}")
                        src |= value

                    case 0b010: # add with carry (adc)
                        self.halt("adc for 0x83 not supported")
                    case 0b011: # subtract with borrow (sbb)
                        self.halt("sbb for 0x83 not supported")
                    case 0b100: # and
                        self.log(f"AND {hex(src)} {hex(value)}")
                        src &= value

                    case 0b101: # sub
                        self.log(f"SUB {hex(src)} {hex(value)}")
                        result = src - value  # perform subtraction
                        self.set_flag(0, value > src)  # Set the carry flag (CF) if AL < imm8
                        self.set_flag(2, bin(result).count(
                            '1') % 2 == 0)  # Set the parity flag (PF) if result has even ammount of ones
                        self.set_flag(6, result == 0)  # Set the zero flag (ZF) if result is zero
                        self.set_flag(7, (result & 0x80) != 0)  # Set the sign flag (SF) if result is negative
                        src = result

                    case 0b110: # xor
                        self.log(f"XOR {hex(src)} {hex(value)}")
                        src ^= value

                    case 0b111: # cmp
                        self.log(f"CMP {hex(src)} {hex(value)}")
                        result = src - value  # perform subtraction
                        self.set_flag(0, value > src)  # Set the carry flag (CF) if AL < imm8
                        self.set_flag(2, bin(result).count(
                            '1') % 2 == 0)  # Set the parity flag (PF) if result has even ammount of ones
                        self.set_flag(6, result == 0)  # Set the zero flag (ZF) if result is zero
                        self.set_flag(7, (result & 0x80) != 0)  # Set the sign flag (SF) if result is negative

                src = src & 0xFFFF
                if modrm.mod == 0b11: # register direct
                    self.set_reg(modrm.rm, src, self.get_size())
                else:
                    self.memory.write(modrm.addr, int.to_bytes(src, byteorder="little", signed=True, length=self.get_size()))
                self.ip += 2 # instruction + imm8

            # JMP ptr16:16/32 = EA ptr16 ptr16/32
            case 0xEA:
                ptr = int.from_bytes(self.fetch(1, 2), 'little')
                segment = int.from_bytes(self.fetch(3, self.get_size()), 'little')
                self.ip = ptr
                self.cs = segment

            # JNC/JNB/JAE rel8 = 73 ib
            case 0x73:
                if self.get_flag(0):  # Check if cary flag (CF) is set
                    self.ip += 2
                    self.log(f'JNC, no jump')
                else:
                    offset = self.fetch(1, 1)
                    offset = int.from_bytes(offset, signed=True)
                    self.ip += offset + 2  # +2 for the opcode and offset byte
                    self.log(f'JNC {hex(offset)}')

            # JNZ/JNE rel8 = 75 ib
            case 0x75:
                if self.get_flag(6):  # Check if zero flag (ZF) is set
                    self.ip += 2
                    self.log(f'JNE, no jump')
                else:
                    offset = self.fetch(1, 1)
                    offset = int.from_bytes(offset, signed=True)
                    self.ip += offset + 2  # +2 for the opcode and offset byte
                    self.log(f'JNE {hex(offset)}')

            # CALL rel16/32 = E8
            case 0xE8:
                size = self.get_size()
                offset = self.fetch(1, size)
                offset = int.from_bytes(offset, 'little', signed=True)
                # save pointer to stack
                self.ip += 1 + size  # +1 for the opcode and size bytes
                self.esp -= size  # decrease stack pointer
                addr = self.resolve_address(self.ss, self.esp, False)  # get address for stack pointer
                self.memory.write(addr, self.ip.to_bytes(size, 'little'))  # write bytes

                self.ip += offset
                self.log(f'CALL += {hex(offset)}')

            # RET near = C3
            case 0xC3:
                size = self.get_size()
                addr = self.resolve_address(self.ss, self.esp, False)  # get address of stack
                data = self.memory.read(addr, size)  # read stack
                value = int.from_bytes(data, 'little')
                self.esp += size # increase stack pointer
                self.ip = value  # set instruction pointer to return address
                self.log(f'RET, returning to {hex(value)}')

            # JMP rel8 = EB
            case 0xEB:
                offset = self.fetch(1, 1)
                offset = int.from_bytes(offset, signed=True)
                self.ip += offset + 2  # +2 for the opcode and offset byte
                self.log(f'JMP {hex(offset)}')

            # INT imm8 = CD+r
            case 0xCD:
                code = self.fetch(1, 1)[0]  # fetch interrupt code
                if code == 0x10:  # BIOS video interrupt
                    if self.get_reg(4,1) == 0x0E:  # Teletype output (AH = 0x0E)
                        char = self.get_reg(0, 1)
                        self.memory.write(0xB8000 + ((self.cursor_y * 80 + self.cursor_x) * 2), char.to_bytes(1, 'little'))
                        self.memory.write(0xB8000 + ((self.cursor_y * 80 + self.cursor_x) * 2) + 1, 0b00001111.to_bytes())
                        self.cursor_x += 1
                        if self.cursor_x >= 80:  # Wrap around at 80 characters
                            self.cursor_x = 0
                            self.cursor_y += 1
                    elif self.get_reg(4, 1) == 0x02: # Set cursor possition
                        self.cursor_x = self.get_reg(2, 1) # dl
                        self.cursor_y = self.get_reg(6, 1) # dh
                    else:
                        self.log(f"Unhandled BIOS interrupt for 0x10, AH={hex(self.get_reg(4,1))}")
                        self.halt()
                elif code == 0x16:  # BIOS keyboard interrupt
                    if self.get_reg(4,1) == 0x00:  # Read keyboard input (AH = 0x00)
                        while len(self.screen.keystrokes) == 0 and not self.screen.exiting:
                            pass
                        if self.screen.exiting:
                            self.halt("Display surface quit")
                        key = self.screen.keystrokes.pop(0)
                        self.set_reg(0, key.ascii, 1) # Set AL to the ascii value of the key
                        self.set_reg(4, key.scancode, 1) # Set AH to the scancode
                    else:
                        self.log(f"Unhandled BIOS interrupt for 0x16, AH={hex(self.get_reg(4,1))}")
                        self.halt()
                else:
                    self.log(f"Unhandled interrupt code: {hex(code)}")
                    self.halt()
                self.ip += 2

            # CLI = FA
            case 0xfa:
                self.set_flag(9, 0)  # Clear the interrupt flag (IF)
                self.log("CLI")
                self.ip += 1

            # XOR r16/32, r/m16/32 = 33+r
            case 0x33:
                modrm = modRM(self)
                mod = modrm.mod
                destreg = modrm.reg
                sourcereg = modrm.rm
                size = self.get_size()
                self.ip += 1

                if mod == 0b11:  # Register to register
                    src = self.get_reg(sourcereg, size)
                    dest = self.get_reg(destreg, size)
                    result = src ^ dest
                    self.set_reg(destreg, result, size)
                    self.log(f'XOR {self.reg_name(destreg, size)}, {self.reg_name(sourcereg, size)}')
                else:
                    addr = modrm.addr
                    src = self.get_reg(sourcereg, size)
                    dest = self.memory.read(addr, size)
                    result = src ^ dest
                    self.set_reg(destreg, result, size)
                    self.log(f'XOR {self.reg_name(destreg, size)}, {hex(addr)}')
            case _:
                self.log(f'unknown opcode: {hex(opcode)}')
                self.ip += 1
                self.halt()

    def match_long(self):
        self.ip += 1
        opcode = self.fetch(0, 1)[0]
        self.log(f"Unknown Opcode: 0F{hex(opcode)}")
        self.ip += 1

    def set_reg(self, idx, value, size):
        if size == 1:
            self._set_8bit(idx, value)
        elif size == 2:
            self._set_16bit(idx, value)
        else:
            self._set_32bit(idx, value)

    def get_reg(self, idx, size):
        if size == 1:
            return self._get_8bit(idx)
        elif size == 2:
            return self._get_16bit(idx)
        else:
            return self._get_32bit(idx)

    @staticmethod
    def sreg_name(idx):
        return ["es", "cs", "ss", "ds", "fs", "gs"][idx]

    def set_sreg(self, idx, value):
        if idx == 0: self.es = value & 0xFFFF
        elif idx == 1: self.cs = value & 0xFFFF
        elif idx == 2: self.ss = value & 0xFFFF
        elif idx == 3: self.ds = value & 0xFFFF
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

    def _set_8bit(self, idx, val):
        if idx == 0: self.eax = (self.eax & 0xFFFFFF00) | (val & 0xFF)
        elif idx == 1: self.ecx = (self.ecx & 0xFFFFFF00) | (val & 0xFF)
        elif idx == 2: self.edx = (self.edx & 0xFFFFFF00) | (val & 0xFF)
        elif idx == 3: self.ebx = (self.ebx & 0xFFFFFF00) | (val & 0xFF)
        elif idx == 4: self.eax = (self.eax & 0xFFFF00FF) | ((val & 0xFF) << 8)
        elif idx == 5: self.ecx = (self.ecx & 0xFFFF00FF) | ((val & 0xFF) << 8)
        elif idx == 6: self.edx = (self.edx & 0xFFFF00FF) | ((val & 0xFF) << 8)
        elif idx == 7: self.ebx = (self.ebx & 0xFFFF00FF) | ((val & 0xFF) << 8)

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

    def _get_8bit(self, idx):
        match idx:
            case 0: return self.eax & 0xFF
            case 1: return self.ecx & 0xFF
            case 2: return self.edx & 0xFF
            case 3: return self.ebx & 0xFF
            case 4: return (self.eax >> 8) & 0xFF
            case 5: return (self.ecx >> 8) & 0xFF
            case 6: return (self.edx >> 8) & 0xFF
            case 7: return (self.ebx >> 8) & 0xFF

    def _get_32bit(self, idx):
        return [self.eax, self.ecx, self.edx, self.ebx,
                self.esp, self.ebp, self.esi, self.edi][idx]

    @staticmethod
    def reg_name(idx, size=4):
        reg_names = {
            1: ["AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"],
            2: ["AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"],
            4: ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
        }
        return reg_names[size][idx]

    def resolve_address(self, segment, offset, overide=True):
        if overide and self.segment_override:
            segment = self.segment_override
        if self.real_mode:
            return (segment * 16) + offset  # Real mode: segment * 16 + offset
        else:
            # Flat protected mode: segments are ignored unless paging/segmentation is used
            # For now, return just the offset (flat model)
            return offset

    def fetch(self, offset=0, size=1):
        addr = self.resolve_address(self.cs, self.ip + offset, False)
        return self.memory.read(addr, size)

    def get_size(self):
        return 2 if self.real_mode or self.operand_override else 4

    def get_flag(self, flag):
        return (self.flags >> flag) & 1

    def set_flag(self, flag, value):
        if value:
            self.flags |= (1 << flag)
        else:
            self.flags &= ~(1 << flag)

    @staticmethod
    def halt(error_message='Halting CPU execution'):
        print(error_message)
        exit()

    def log(self, message):
        if self.debug_mode:
            print(f"[CPU] {message}")