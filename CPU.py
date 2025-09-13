from math import floor

from MEM import AddressSpace
from modRM import ModRM

reg_names = {
    1: ["AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"],
    2: ["AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"],
    4: ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
}


class CPU:
    def __init__(self, debug_mode: bool = False):
        # https://wiki.osdev.org/CPU_Registers_x86
        # Accumulator, Base, Counter, Data, Source, Destination, Stack Pointer, Stack Base Pointer
        # General-purpose registers
        self.eax = self.ebx = self.ecx = self.edx = 0
        self.esi = self.edi = self.ebp = 0
        self.esp: int = 0x7C00  # Stack pointer initialized to before the boot sector
        self.ip: int = 0xFFF0

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
        self.flags = 0
        self.cr0 = self.cr2 = self.cr3 = self.cr4 = self.cr8 = 0
        self.cr1 = self.cr5 = self.cr6 = self.cr7 = None
        self.xcr0 = 0

        # Protected mode descriptor registers
        self.gdtr = self.ldtr = self.idtr = 0

        # Internal state
        self.video_mode = 0x0E
        self.memory: AddressSpace = AddressSpace()
        self.modrm = ModRM(self)
        self.screen = None
        self.debug_val = 0
        self.debug_mode = debug_mode
        self.disks = []

        # CPU state
        self.address_size = 2
        self.size = 2
        self.real_mode = True
        self.cursor_x = 0
        self.cursor_y = 0

        # overrides
        self.override_count = 0
        self.size_override = False
        self.segment_override = None
        self.address_size_override = False

    def unsigned(self, val: int, size: int = 0) -> int:
        if not size: size = self.size
        return val & ((1 << (size * 8)) - 1)

    def signed(self, val: int, size: int = 0) -> int:
        if not size: size = self.size
        bits = size * 8
        max_unsigned = 1 << bits
        if val >= max_unsigned: self.halt(f"Value exceeds maximum unsigned value for size {size}: {val:x}")
        sign_bit = 1 << (bits - 1)
        if val & sign_bit:  # get the sign bit of val, if set, it is negative
            val -= max_unsigned
        return val

    def execute(self) -> None:
        # Fetch prefix bytes first
        prefix = self.fetch()[0]
        self.log(f"Instruction: {prefix:x}")
        if self.override_count < 4:
            prefixes = True
            match prefix:
                case 0x66:
                    self.size_override = True
                case 0x36:
                    self.segment_override = self.ss
                case 0x26:
                    self.segment_override = self.es
                case 0x2e:
                    self.segment_override = self.cs
                case 0x3e:
                    self.segment_override = self.ds
                case 0x64:
                    self.segment_override = self.fs
                case 0x65:
                    self.segment_override = self.gs
                case 0x67:
                    self.address_size_override = True
                case _:
                    prefixes = False
            if prefixes:
                self.ip += 1
                self.override_count += 1
                self.execute()
                return

        self.get_size()
        if prefix == 0x0F:
            self.match_long()
        else:
            self.match_short()

        self.size_override = False
        self.address_size_override = False
        self.segment_override = None
        self.override_count = 0

    def match_short(self) -> None:
        opcode = self.fetch()[0]
        match opcode:
            # ADD r/m16/32, r16/32 = 01 /r
            case 0x01:
                modrm = self.modrm()
                src = self.signed(modrm.read())
                value = self.signed(self.get_reg(modrm.reg, self.size))
                self.log(f"ADD {src:x} {value:x}")
                self.set_flags_add(src, value)
                src += value
                modrm.write(src)
                self.ip += 1

            # ADD r16/32, r/m16/32 = 03 /r
            case 0x03:
                modrm = self.modrm()
                value = self.signed(modrm.read())
                src = self.signed(self.get_reg(modrm.reg, self.size))
                self.log(f"ADD {src:x} {value:x}")
                self.set_flags_add(src, value)
                src += value
                self.set_reg(modrm.reg, src, self.size)
                self.ip += 1

            # ADD e/ax, imm16/32 = 05 iw
            case 0x05:
                value = self.signed(int.from_bytes(self.fetch(1, self.size), byteorder="little"))
                src = self.signed(self.get_reg(0, self.size))
                self.log(f"ADD E/AX={src:x} {value:x}, ={src+value:x}")
                self.set_flags_add(src, value)
                src += value
                self.set_reg(0, src, self.size)
                self.ip += 1 + self.size

            # PUSH ES = 06
            case 0x06:
                self.esp -= 2  # decrease stack pointer
                addr = self.resolve_address(self.ss, self.esp, False)  # get address for stack pointer
                self.memory.write(addr, self.es.to_bytes(length=2, byteorder="little"))  # write bytes
                self.log(f"PUSH ES")
                self.ip += 1

            # POP ES = 07
            case 0x07:
                addr = self.resolve_address(self.ss, self.esp, False)  # get address of stack
                data = self.memory.read(addr, 2)  # read stack
                value = int.from_bytes(data, byteorder="little")
                self.es = value
                self.esp += 2
                self.log(f"POP ES")
                self.ip += 1

            # or r/m8 r8 = 08 /r
            case 0x08:
                modrm = self.modrm()
                src = modrm.read(1)
                src |= self.get_reg(modrm.reg, 1)
                modrm.write(src, 1)
                self.log(f"OR {src:x} {self.get_reg(modrm.reg, 1):x}")
                self.set_flags_logic(src, 1)
                self.ip += 1

            # OR r8, r/m8 = 0x0A /r
            case 0x0A:
                modrm = self.modrm()
                src = self.get_reg(modrm.reg, 1)
                value = modrm.read(1)

                self.log(f"OR {self.reg_name(modrm.reg, 1)} {value:x}")
                src |= value
                self.set_flags_logic(src, 1)
                self.set_reg(modrm.reg, src, 1)  # Store result back in register
                self.ip += 1

            # ADC r/m16/32, r16/32 = 11 /r
            case 0x11:  # sdsdfsdfahadfdfgfdgdfdrfg
                modrm = self.modrm()
                src = self.signed(modrm.read())
                value = self.signed(self.get_reg(modrm.reg, self.size))
                self.log(f"ADC {value:x} {src:x}, {self.get_flag(0)}")
                self.set_flags_add(src, value, self.size, 1)
                src += value + self.get_flag(0)  # add with carry
                modrm.write(src)
                self.ip += 1

            # PUSH DS = 1E
            case 0x1E:
                self.esp -= 2  # decrease stack pointer
                addr = self.resolve_address(self.ss, self.esp, False)  # get address for stack pointer
                self.memory.write(addr, self.ds.to_bytes(length=2, byteorder="little"))  # write bytes
                self.log(f"PUSH DS")
                self.ip += 1

            # POP DS = 1F
            case 0x1F:
                addr = self.resolve_address(self.ss, self.esp, False)  # get address of stack
                data = self.memory.read(addr, 2)  # read stack
                value = int.from_bytes(data, byteorder="little")
                self.ds = value
                self.esp += 2
                self.log(f"POP DS")
                self.ip += 1

            # SUB r8, r/m8 = 2A /r
            case 0x2a:
                modrm = self.modrm()
                value = self.signed(modrm.read(1), 1)
                src = self.signed(self.get_reg(modrm.reg, 1), 1)
                self.log(f"SUB {src:x} {value:x}")
                self.set_flags_sub(src, value, 1)
                src -= value
                self.set_reg(modrm.reg, src, 1)
                self.ip += 1

            # SUB r16/32, r/m16/32 = 2B /r
            case 0x2b:
                modrm = self.modrm()
                value = self.signed(modrm.read())
                src = self.signed(self.get_reg(modrm.reg, self.size))
                self.log(f"SUB {src:x} {value:x}")
                self.set_flags_sub(src, value)
                src -= value
                self.set_reg(modrm.reg, src, self.size)
                self.ip += 1

            # XOR r/m8, r8 = 30 /r
            case 0x30:
                modrm = self.modrm()
                src = modrm.read(1)
                src ^= self.get_reg(modrm.reg, 1)
                self.set_flags_logic(src, 1)
                modrm.write(src, 1)
                self.log(f"XOR r/m8, {self.reg_name(modrm.reg, 1)}")
                self.ip += 1

            # XOR r/m16/32, r16/32 = 31 /r
            case 0x31:
                modrm = self.modrm()
                src = modrm.read()
                src ^= self.get_reg(modrm.reg, self.size)
                modrm.write(src)
                self.set_flags_logic(src)
                self.log(f"XOR r/m16/32, {self.reg_name(modrm.reg, self.size)}")
                self.ip += 1

            # XOR r16/32, r/m16/32 = 33 /r
            case 0x33:
                modrm = self.modrm()
                src = self.get_reg(modrm.reg, self.size)
                value = modrm.read()
                src ^= value
                self.set_flags_logic(src)
                self.set_reg(modrm.reg, src, self.size)
                self.log(f'XOR {self.reg_name(modrm.reg, self.size)}, {value:x}')
                self.ip += 1

            # CMP AL, imm8 = 3C ib
            case 0x3C:
                imm = self.fetch(1)[0]  # fetch immediate byte
                src = self.get_reg(0, 1)  # AL register
                self.log(f'CMP AL, {src:x}')
                self.set_flags_sub(src, imm, 1)
                src -= imm  # perform subtraction
                self.ip += 2

            # CMP AX, imm16/32 = 3D ib
            case 0x3D:
                imm = int.from_bytes(self.fetch(1, self.size), byteorder="little")  # fetch immediate byte
                src = self.get_reg(0, self.size)  # AX register
                self.log(f'CMP AX, {src:x}')
                self.set_flags_sub(src, imm)
                self.ip += 1 + self.size

            # INC reg16/32 = 40+r
            case 0x40 | 0x41 | 0x42 | 0x43 | 0x44 | 0x45 | 0x46 | 0x47:
                reg = opcode - 0x40
                src = self.get_reg(reg, self.size)
                self.log(f"INC {src:x}")
                self.set_flags_add(src, 1)
                src += 1
                self.set_reg(reg, src, self.size)
                self.ip += 1

            # DEC reg16/32 = 48+r
            case 0x48 | 0x49 | 0x4a | 0x4b | 0x4c | 0x4d | 0x4e | 0x4f:
                reg = opcode - 0x48
                src = self.get_reg(reg, self.size)
                self.log(f"DEC {src:x}")
                self.set_flags_sub(src, 1)
                src -= 1
                self.set_reg(reg, src, self.size)
                self.ip += 1

            # PUSH r16/32 = 50+r
            case 0x50 | 0x51 | 0x52 | 0x53 | 0x54 | 0x55 | 0x56 | 0x57:
                reg = opcode - 0x50  # get register id
                value = self.get_reg(reg, self.size)  # get register value
                self.esp -= self.size  # decrease stack pointer
                addr = self.resolve_address(self.ss, self.esp, False)  # get address for stack pointer
                self.memory.write(addr, value.to_bytes(length=self.size, byteorder="little"))  # write bytes
                self.log(f"PUSH {self.reg_name(reg, self.size)}")
                self.ip += 1

            # POP r16/32 = 58+r
            case 0x58 | 0x59 | 0x5A | 0x5B | 0x5C | 0x5D | 0x5E | 0x5F:
                reg = opcode - 0x58  # get register id
                addr = self.resolve_address(self.ss, self.esp, False)  # get address of stack
                data = self.memory.read(addr, self.size)  # read stack
                value = int.from_bytes(data, byteorder="little")
                self.set_reg(reg, value, self.size)  # set register value
                self.esp += self.size  # increase stack pointer
                self.log(f"POP {self.reg_name(reg, self.size)}")
                self.ip += 1

            # JC/JB rel8 = 72 ib
            case 0x72:
                if not self.get_flag(0):  # Check if cary flag (CF) is set
                    self.ip += 2
                    self.log(f'JC, no jump')
                else:
                    offset = self.fetch(1)[0]
                    offset = self.signed(offset, 1)
                    self.ip += offset + 2  # +2 for the opcode and offset byte
                    self.log(f'JC {offset:x}')

            # JNC/JNB/JAE rel8 = 73 ib
            case 0x73:
                if self.get_flag(0):  # Check if cary flag (CF) is set
                    self.ip += 2
                    self.log(f'JNC, no jump')
                else:
                    offset = self.fetch(1)[0]
                    offset = self.signed(offset, 1)
                    self.ip += offset + 2  # +2 for the opcode and offset byte
                    self.log(f'JNC {offset:x}')

            # JE rel8 = 74 ib
            case 0x74:
                if not self.get_flag(6):  # Check if zero flag (ZF) is set
                    self.ip += 2
                    self.log(f'JE, no jump')
                else:
                    offset = self.fetch(1)[0]
                    offset = self.signed(offset, 1)
                    self.ip += offset + 2  # +2 for the opcode and offset byte
                    self.log(f'JE {offset:x}')

            # JNZ/JNE rel8 = 75 ib
            case 0x75:
                if self.get_flag(6):  # Check if zero flag (ZF) is set
                    self.ip += 2
                    self.log(f'JNE, no jump')
                else:
                    offset = self.fetch(1)[0]
                    offset = self.signed(offset, 1)
                    self.ip += offset + 2  # +2 for the opcode and offset byte
                    self.log(f'JNE {offset:x}')

            # JNS rel8 = 79 ib
            case 0x79:
                if self.get_flag(7):  # Check if sign flag (SF) is set
                    self.ip += 2
                    self.log(f'JNS, no jump')
                else:
                    offset = self.fetch(1)[0]
                    offset = self.signed(offset, 1)
                    self.ip += offset + 2  # +2 for the opcode and offset byte
                    self.log(f'JNS {offset:x}')

            # SUB, ADD, OR, ADC, SBB, AND, SUB, XOR, CMP
            # r/m8,     imm8     = 80 /r
            # r/m16/32, imm16/32 = 81 /r
            # r/m16/32, imm8     = 83 /r
            case 0x80 | 0x81 | 0x83:
                modrm = self.modrm()
                mode = modrm.reg
                if opcode == 0x80:
                    src = self.signed(modrm.read(1), 1)
                else:
                    src = self.signed(modrm.read())
                if opcode == 0x81:
                    size = self.size
                    value = self.signed(int.from_bytes(self.fetch(1, self.size), byteorder="little"))
                else:
                    size = 1
                    value = self.signed(int.from_bytes(self.fetch(1), byteorder="little"), 1)
                _ = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"][mode]
                self.log(f"{_} {src:x} {value:x}")
                match mode:
                    case 0b000:
                        self.set_flags_add(src, value, size)
                        src += value  # add
                    case 0b001:
                        src |= value  # or
                        self.set_flags_logic(src, size)
                    case 0b010:
                        self.set_flags_add(src, value, size, 1)
                        src += value + self.get_flag(0)  # adc
                    case 0b011:
                        self.set_flags_sub(src, value, size, 1)
                        src -= value + self.get_flag(0)  # sbb
                    case 0b100:
                        src &= value  # and
                        self.set_flags_logic(src, size)
                    case 0b101:
                        self.set_flags_sub(src, value, size)
                        src -= value  # sub
                    case 0b110:
                        src ^= value  # xor
                        self.set_flags_logic(src, size)
                    case 0b111:
                        self.set_flags_sub(src, value, size)  # cmp
                src &= (1 << (size * 8)) - 1
                if opcode == 0x80:
                    modrm.write(src, 1)
                else:
                    modrm.write(src)
                self.ip += 1 + size

            # XCHG r8, rm8 = 86 /r
            case 0x86:
                modrm = self.modrm()
                r = self.get_reg(modrm.reg, 1)
                self.set_reg(modrm.reg, modrm.read(1), 1)
                modrm.write(r, 1)
                self.log(f"XCHG {self.reg_name(modrm.reg, 1)}, rm8")
                self.ip += 1

            # MOV r/m8, r8 = 88 /r
            case 0x88:
                modrm = self.modrm()
                value = self.get_reg(modrm.reg, 1)
                modrm.write(value, 1)
                self.log(f"MOV r/m8, {self.reg_name(modrm.reg, 1)}={value:x}")
                self.ip += 1

            # MOV r/m16/32, r16/32 = 89 /r
            case 0x89:
                modrm = self.modrm()
                value = self.get_reg(modrm.reg, self.size)
                modrm.write(value)
                self.log(f"MOV rm16/32, r16/32={value:x}")
                self.ip += 1

            # MOV r8, r/m8 = 8A /r
            case 0x8A:
                modrm = self.modrm()
                value = modrm.read(1)
                self.log(f"MOV r8, rm8={value:x}")
                self.set_reg(modrm.reg, value, 1)
                self.ip += 1

            # MOV r16/32, r/m16/32 = 8B /r
            case 0x8B:
                modrm = self.modrm()
                value = modrm.read()
                self.set_reg(modrm.reg, value, self.size)
                self.log(f"MOV r16/32, rm16/32={value:x}")
                self.ip += 1

            # MOV r16/r32/m16, Sreg = 8C /r
            case 0x8C:
                modrm = self.modrm()
                value = self.get_sreg(modrm.reg)
                modrm.write(value, 2)
                self.log(f"MOV rm16/32, {self.sreg_name(modrm.reg)}={value:x}")
                self.ip += 1

            # MOV Sreg, r/m16/32 = 8E /r
            case 0x8E:
                modrm = self.modrm()
                value = modrm.read()
                self.set_sreg(modrm.reg, value)
                self.log(f"MOV {self.sreg_name(modrm.reg)}, rm16/32={value:x}")
                self.ip += 1

            # NOP = 90
            case 0x90:
                self.log("NOP")
                self.ip += 1

            # XCHG r16/32, EAX/AX = 90+r
            case 0x91 | 0x92 | 0x93 | 0x94 | 0x95 | 0x96 | 0x97:
                reg = opcode - 0x90  # get register id
                ax = self.get_reg(0, self.size)
                self.set_reg(0, self.get_reg(reg, self.size), self.size)
                self.set_reg(reg, ax, self.size)
                self.log(f"XCHG {self.reg_name(reg, self.size)}, AX")
                self.ip += 1

            # CBW AL/EAX = 98
            case 0x98:
                if self.size == 2:
                    al = self.get_reg(0, 1)
                    ah = 0xFF if (al & 0x80) else 0x00
                    self.set_reg(4, ah, 1)  # AH
                elif self.size == 4:
                    ax = self.get_reg(0, 2)
                    if ax & 0x8000:
                        self.eax = ax | 0xFFFF0000
                    else:
                        self.eax = ax & 0x0000FFFF
                else:
                    print(f"wrong size {self.size} for cbw")
                self.log("cbw ax")
                self.ip += 1

            # MOV AL, moffs8 = A0
            case 0xA0:
                addr = int.from_bytes(self.fetch(1, self.address_size), byteorder="little")
                addr = self.resolve_address(self.ds, addr)
                value = self.memory.read(addr, 1)[0]
                self.set_reg(0, value, 1)  # AL register
                self.ip += 1 + self.address_size
                self.log(f"MOV AL, {self.get_reg(0, 1)}, moffs8={addr:x}={value:x}")

            # MOV EAX, moffs16/32 = A1
            case 0xA1:
                addr = int.from_bytes(self.fetch(1, self.address_size), byteorder="little")
                addr = self.resolve_address(self.ds, addr)
                value = int.from_bytes(self.memory.read(addr, self.size), byteorder="little")
                self.set_reg(0, value, self.size)
                self.ip += 1 + self.address_size
                self.log(f"MOV E/AX, moffs16/32={addr:x}={value:x}")

            # STOSB = AA
            case 0xAA:
                addr = self.resolve_address(self.es, self.edi)  # Address in ES:DI
                byte = self.get_reg(0, 1)  # Load byte from AL
                self.memory.write(addr, byte.to_bytes())

                self.edi += (self.get_flag(10) * -2) + 1  # get direction flag (DF) (1 = -1, 0 = +1)
                self.ip += 1
                self.log(f'STOSB => AL = {byte:x}, EDI = {self.edi:x}, resolved address = {addr:x}')

            # STOSW = AB
            case 0xAB:
                addr = self.resolve_address(self.es, self.edi)  # Address in ES:DI
                self.memory.write(addr, self.get_reg(0, self.size).to_bytes(length=self.size, byteorder="little"))

                self.edi += ((self.get_flag(10) * -2) + 1) * 2  # get direction flag (DF) (1 = -2, 0 = +2)
                self.ip += 1
                self.log(f'STOSW => E/AX = {self.eax:x}, EDI = {self.edi:x}, resolved address = {addr:x}')

            # LODSB = AC
            case 0xAC:
                addr = self.resolve_address(self.ds, self.esi)  # Address in DS:ESI
                byte = self.memory.read(addr, 1)[0]
                self.set_reg(0, byte, 1)  # Load byte into AL
                self.esi += (self.get_flag(10) * -2) + 1  # get direction flag (DF) (1 = -1, 0 = +1)
                self.ip += 1
                self.log(f'LODSB => AL = {byte:x}, ESI = {self.esi:x}, resolved address = {addr:x}')

            # MOV r8, imm8 = B0+r
            case 0xB0 | 0xB1 | 0xB2 | 0xB3 | 0xB4 | 0xB5 | 0xB6 | 0xB7:
                reg = opcode - 0xB0  # get register id
                imm = self.fetch(1)[0]
                self.set_reg(reg, imm, 1)
                self.log(f"MOV {self.reg_name(reg, 1)}, imm8={imm:x}")
                self.ip += 2

            # MOV r16/32, imm16/32 = B8+r
            case 0xB8 | 0xB9 | 0xBA | 0xBB | 0xBC | 0xBD | 0xBE | 0xBF:
                reg = opcode - 0xB8  # get register id
                imm = int.from_bytes(self.fetch(1, self.size), byteorder="little")
                self.set_reg(reg, imm, self.size)
                self.log(f"MOV {self.reg_name(reg, self.size)}, imm16/32={imm:x}")
                self.ip += 1 + self.size

            # RET near = C3
            case 0xC3:
                addr = self.resolve_address(self.ss, self.esp, False)  # get address of stack
                data = self.memory.read(addr, self.size)  # read stack
                value = int.from_bytes(data, byteorder="little")
                self.esp += self.size  # increase stack pointer
                self.ip = value  # set instruction pointer to return address
                self.log(f'RET, returning to {value:x}')

            # LES r16/32, m16:16/32 = C4 /r
            case 0xC4:
                modrm = self.modrm()
                addr = modrm.addr

                # Read offset and segment from memory
                raw = self.memory.read(addr, self.size + 2)
                offset_val = int.from_bytes(raw[:self.size], byteorder="little")
                segment_val = int.from_bytes(raw[self.size:], byteorder="little")

                self.set_reg(modrm.reg, offset_val, self.size)
                self.es = segment_val

                self.log(f"LES {self.reg_name(modrm.reg, self.size)}, [{addr:x}] => {offset_val:x}:{segment_val:x}")
                self.ip += 1

            # LDS r16/32, m16:32/m32:48 = C5 /r
            case 0xC5:
                modrm = self.modrm()
                # Read offset and segment from memory
                self.ds = int.from_bytes(self.memory.read(modrm.addr, self.size), byteorder="little")
                self.set_reg(modrm.reg,
                             int.from_bytes(self.memory.read(modrm.addr + self.size, self.size), byteorder="little"),
                             self.size)
                self.log(
                    f"LDS:{self.reg_name(modrm.reg, self.size)}, [{modrm.addr:x}] => DS={self.ds:x}, {self.get_reg(modrm.reg, self.size):x}")
                self.ip += 1

            # MOV r/m8 imm8 = C6 /0 ib
            case 0xC6:
                modrm = self.modrm()
                if modrm.reg != 0: self.halt(f"MOV r/m8 imm8 with reg={modrm.mod:x}")
                value = self.fetch(1)[0]
                self.log(f"MOV rm8, imm8={value:x}")
                modrm.write(value, 1)
                self.ip += 2

            # MOV r/m16/32, imm16/32 = C7 /0 imm
            case 0xC7:
                modrm = self.modrm()
                value = int.from_bytes(self.fetch(1, self.size), byteorder="little")
                if modrm.reg: self.halt("REG is non-0 while executing /0 instruction")
                modrm.write(value)
                self.log(f"MOV rm16/32, imm16/32={value:x}")
                self.ip += 1 + self.size

            # INT imm8 = CD r
            case 0xCD:
                code = self.fetch(1)[0]  # fetch interrupt code
                if code == 0x10:  # BIOS video interrupt
                    if self.get_reg(4, 1) == 0x0E:  # Teletype output (AH = 0x0E)
                        self.video_mode = 0x0E
                        char = self.get_reg(0, 1)
                        if char == 0x0a:  # Newline charact
                            self.cursor_y += 1
                        elif char == 0x0d:  # Carriage return character
                            self.cursor_x = 0
                        else:
                            self.memory.write(0xB8000 + ((self.cursor_y * 80 + self.cursor_x) * 2), char.to_bytes())
                            self.memory.write(0xB8000 + ((self.cursor_y * 80 + self.cursor_x) * 2) + 1,
                                              0b00001111.to_bytes())
                            self.cursor_x += 1
                        if self.cursor_x >= 80:  # Wrap around at 80 characters
                            self.cursor_x = 0
                            self.cursor_y += 1
                        if self.cursor_y >= 25:  # Wrap around at 25 characters
                            self.cursor_y = 0
                    elif self.get_reg(4, 1) == 0x02:  # Set cursor possition
                        self.cursor_x = self.get_reg(2, 1)  # dl
                        self.cursor_y = self.get_reg(6, 1)  # dh
                    elif self.get_reg(4, 1) == 0x00:  # Set video mode
                        mode = self.get_reg(0, 1)  # AL
                        match mode:
                            case 0x13:  # VGA Mode 13h (320x200x8bpp)
                                self.video_mode = 0x13
                    else:
                        self.log(f"Unhandled BIOS interrupt for 0x10, AH={self.get_reg(4, 1):x}")
                        self.halt()

                elif code == 0x16:  # BIOS keyboard interrupt
                    if self.get_reg(4, 1) == 0x00:  # Read keyboard input (AH = 0x00)
                        while len(self.screen.keystrokes) == 0 and not self.screen.exiting:
                            pass
                        if self.screen.exiting:
                            self.halt("Display surface quit")
                        key = self.screen.keystrokes.pop(0)
                        self.set_reg(0, key.ascii, 1)  # Set AL to the ascii value of the key
                        self.set_reg(4, key.scancode, 1)  # Set AH to the scancode
                    else:
                        self.log(f"Unhandled BIOS interrupt for 0x16, AH={self.get_reg(4, 1):x}")
                        self.halt()

                elif code == 0x13:  # BIOS disk interrupt
                    disk = self.get_reg(2, 1)  # DL
                    status = 0
                    fail = 0
                    match self.get_reg(4, 1):  # AH
                        case 0x00:  # Reset Disk System
                            if disk not in self.disks:
                                status = 0xAA  # drive not ready
                                fail = 1
                            self.log(f"Reset Disk {disk:x}")

                        case 0x02: # Read Sectors From Drive
                            data = self.disks[disk]
                            # sector = (cylinder * heads_per_cylinder + head) * sectors_per_head + sector - 1
                            # sector = (CH * 2 + DH) * 63 + CL - 1
                            sector = (self.get_reg(5, 1) * 2 + self.get_reg(6, 1)) * 63 + self.get_reg(1, 1) - 1
                            count = self.get_reg(0, 1)
                            try:
                                data = data[sector * 512:(sector + count) * 512]  # sector read count = AL * 512
                                self.memory.write(self.resolve_address(self.es, self.get_reg(3, 2)), data)
                            except IndexError:
                                fail = 1
                                status = 0xAA
                            self.log(f"Read {count} Sectors From Drive {disk:x} at sector {sector}")

                        case _:
                            self.halt(f"unknown function {self.get_reg(4, 1):x} for BIOS disk interrupt 0x13")
                    self.set_reg(4, status, 1)  # ah = status code
                    self.set_flag(0, fail)  # set carry flag if fail
                else:
                    self.log(f"Unhandled interrupt code: {code:x}")
                    self.halt()
                self.ip += 2

            # ROL/ROR/RCL/RCR/SHL/SHR/(SHL?/NOP)/SAR r/m8, 1
            case 0xD0:
                modrm = self.modrm()
                val = modrm.read(1)
                match modrm.reg:
                    case 1:
                        mode = "ROR"
                        self.set_flag(0, val & 1)
                        val |= (val & 1) << 9
                        val >>= 1
                    case 4:
                        mode = "SHL"
                        self.set_flag(0, val >> 8)
                        val <<= 1
                    case _:
                        mode = "unknown"
                        self.halt(f"Unknown option for 0xD0: /{modrm.reg}")

                self.log(f"{mode} r/m8 1")
                modrm.write(val, 1)
                self.ip += 1

            # ROL/ROR/RCL/RCR/SHL/SHR/(SHL?/NOP)/SAR r/m16/32, 1
            case 0xD1:
                modrm = self.modrm()
                val = modrm.read()
                match modrm.reg:
                    case 1:
                        mode = "ROR"
                        self.set_flag(0, val & 1)
                        val |= (val & 1) << ((self.size * 8) + 1)
                        val >>= 1
                    case 4:
                        mode = "SHL"
                        self.set_flag(0, val >> (self.size * 8))
                        val <<= 1
                    case _:
                        mode = "unknown"
                        self.halt(f"Unknown option for 0xD1: /{modrm.reg}")

                self.log(f"{mode} r/m16/32, 1")
                modrm.write(val)
                self.ip += 1

            # loop rel8 = E2 cb
            case 0xE2:
                ecx = self.get_reg(1, self.size)
                ecx -= 1
                self.set_reg(1, ecx, self.size)
                if ecx == 0:
                    self.ip += 2
                    self.log(f'loop, no jump, ecx = 0')
                else:
                    offset = self.fetch(1)[0]
                    offset = self.signed(offset, 1)
                    self.ip += offset + 2  # +2 for the opcode and offset byte
                    self.log(f'loop {offset:x}, ecx = {ecx}')

            # CALL rel16/32 = E8
            case 0xE8:
                offset = self.fetch(1, self.size)
                offset = self.signed(int.from_bytes(offset, byteorder="little", signed=True))
                # save pointer to stack
                self.ip += 1 + self.size  # +1 for the opcode and size bytes
                self.esp -= self.size  # decrease stack pointer
                addr = self.resolve_address(self.ss, self.esp, False)  # get address for stack pointer
                self.memory.write(addr, self.ip.to_bytes(length=self.size, byteorder="little"))  # write bytes

                self.ip += offset
                self.log(f'CALL += {offset:x}')

            # JMP rel16/32 = E9
            case 0xE9:
                offset = self.signed(int.from_bytes(self.fetch(1, self.size), byteorder="little"))
                self.ip += offset + 1 + self.size
                self.log(f'JMP {offset:x}')

            # JMP ptr16:16/32 = EA ptr16:ptr16/32
            case 0xEA:
                ptr = int.from_bytes(self.fetch(1, self.size), byteorder="little")
                segment = int.from_bytes(self.fetch(1 + self.size, 2), byteorder="little")
                self.ip = ptr
                self.cs = segment

            # JMP rel8 = EB
            case 0xEB:
                offset = self.fetch(1)[0]
                offset = self.signed(offset, 1)
                self.ip += offset + 2  # +2 for the opcode and offset byte
                self.log(f'JMP {offset:x}')

            # REP/E = F3
            case 0xF3:
                match self.fetch(1)[0]:
                    case 0xA4:
                        # Move CX bytes from DS:[E/SI] to ES:[E/DI] with respect to DF. (1 - (self.get_flag(10) * 2))
                        ecx = self.get_reg(1, self.size)
                        df = self.get_flag(10)
                        esi = self.get_reg(6, self.size) - (ecx * df)
                        edi = self.get_reg(7, self.size) - (ecx * df)
                        # do copy
                        data = self.memory.read(self.resolve_address(self.ds, esi), ecx)
                        addr = self.resolve_address(self.es, edi)
                        self.memory.write(addr, data)
                        if not df:
                            esi += ecx
                            edi += ecx
                        self.set_reg(6, esi, self.size)
                        self.set_reg(7, edi, self.size)
                        self.set_reg(1, 0, self.size)
                        self.log(f"REP MOV m8 m8")
                    case 0xa6:
                        # compare e/cx bytes from ES:[E/DI] and DS:[E/SI], stop when zf != 0
                        src = dest = 0
                        for _ in range(self.get_reg(1, self.size)):
                            src = self.memory.read(self.resolve_address(self.es, self.get_reg(7, self.size)), 1)
                            dest = self.memory.read(self.resolve_address(self.es, self.get_reg(7, self.size)), 1)
                            if src != dest: break
                        self.set_flags_sub(self.signed(src[0], 1), self.signed(dest[0], 1), 1)
                        self.log(f"REPE  m8 m8")
                    case _:
                        self.halt(f"Rep prefix {self.fetch(1)[0]:x} not supported")
                self.ip += 2

            # HLT = F4
            case 0xF4:
                self.halt("HALT INSTRUCTION")
                self.ip += 1

            # TEST, TEST, NOT, NEG, MUL, IMUL, DIV, IDIV e/ax, r/m8 = F7 /r
            case 0xF6:
                modrm = self.modrm()
                src = self.get_reg(0, 1) # AL register
                value = modrm.read(1)
                self.ip += 1
                match modrm.reg:
                    case 4:  # unsigned multiply
                        # ax := al * r/m8
                        self.log(f"MUL al, {value:x}")
                        src *= value
                        upper = src & 0xFF00
                        lower = src & 0x00FF
                        self.set_reg(2, upper >> 32, 4)  # Set AH
                        self.set_reg(0, lower, 4)  # set AL

                        self.set_flag(0, upper != 0)  # set carry if upper is not zero
                        self.set_flag(11, upper != 0)  # set overflow if upper is not zero
                    case 6:
                        # ax := ax / r/m8
                        src = self.get_reg(0, 2)
                        self.log(f"DIV ax, {value:x}")
                        q = floor(src / value)
                        r = src % value
                        self.set_reg(4, r, 1)
                        self.set_reg(0, q, 1)
                    case _:
                        self.halt(f"Unsupported F6 /r operation: {modrm.reg}")

            # TEST, TEST, NOT, NEG, MUL, IMUL, DIV, IDIV e/ax, r/m16/32 = F7 /r
            case 0xF7:
                modrm = self.modrm()
                src = self.get_reg(0, self.size)  # EAX/AX register
                value = modrm.read()

                self.ip += 1
                match modrm.reg:
                    case 4:  # unsigned multiply
                        # edx/dx:eax/ax := eax/ax * r/m16/32
                        self.log(f"MUL e/ax, {value:x}")
                        if self.size == 2:  # dx:ax = src * value
                            src *= value
                            upper = src & 0xFFFF0000
                            lower = src & 0x0000FFFF
                            self.set_reg(2, upper >> 16, 2)  # Set DX
                            self.set_reg(0, lower, 2)  # Set AX
                        elif self.size == 4:  # edx:eax = src * value
                            src *= value
                            upper = src & 0xFFFFFFFF00000000
                            lower = src & 0x00000000FFFFFFFF
                            self.set_reg(2, upper >> 32, 4)  # Set EDX
                            self.set_reg(0, lower, 4)  # set EAX
                        else:
                            self.halt(f"invalid size to multiply: {self.size}")
                            upper = 0
                        self.set_flag(0, upper != 0)  # set carry if upper is not zero
                        self.set_flag(11, upper != 0)  # set overflow if upper is not zero
                    case 6:
                        # edx/dx:eax/ax := eax/ax / r/m16/32
                        src = (self.get_reg(2, self.size) << (self.size * 8)) | self.get_reg(0, self.size)
                        self.log(f"DIV e/dx:e/ax, {value:x}")
                        q = floor(src / value)
                        r = src % value
                        self.set_reg(2, r, self.size)
                        self.set_reg(0, q, self.size)
                    case _:
                        self.halt(f"Unsupported F7 /r operation: {modrm.reg}")

            # CLC = F8
            case 0xF8:
                self.set_flag(0, 0)  # Clear the carry flag (CF)
                self.log("CLC")
                self.ip += 1

            # STC = F9
            case 0xF9:
                self.set_flag(0, 1)  # set the carry flag (CF)
                self.log("STC")
                self.ip += 1

            # CLI = FA
            case 0xFA:
                self.set_flag(9, 0)  # Clear the interrupt flag (IF)
                self.log("CLI")
                self.ip += 1

            # STI = FB
            case 0xFB:
                self.set_flag(9, 1)  # set the interrupt flag (IF)
                self.log("STI")
                self.ip += 1

            # CLD = FC
            case 0xFC:
                self.set_flag(10, 0)  # Clear the direction flag (DF)
                self.log("CLD")
                self.ip += 1

            # STD = FD
            case 0xFD:
                self.set_flag(10, 1)  # set the direction flag (DF)
                self.log("STD")
                self.ip += 1

            # INC/DEC r/m8 = FE /01
            case 0xFE:
                modrm = self.modrm()
                src = self.signed(modrm.read(1), 1)
                if modrm.reg == 0:
                    self.set_flags_add(src, 1, 1)
                    src += 1
                elif modrm.reg == 1:
                    self.set_flags_sub(src, 1, 1)
                    src -= 1
                else: self.halt(f"inc/dec 0xFE with /{modrm.reg:b}")
                self.log(f"INC/DEC {src:x}")
                modrm.write(src, 1)
                self.ip += 1

            case _:
                self.log(f'unknown opcode: {opcode:x}')
                self.ip += 1
                self.halt()

    def match_long(self) -> None:
        self.ip += 1
        opcode = self.fetch()[0]
        match opcode:
            case 0xff:
                input("Opcode 0x0F FF, debug freeze. Press enter to continue.")
            case _:
                self.log(f"Unknown Opcode: 0F{opcode:x}")
                self.halt()
        self.ip += 1

    def set_reg(self, idx: int, value: int, size: int) -> None:
        if size == 1:
            self._set_8bit(idx, value)
        elif size == 2:
            self._set_16bit(idx, value)
        else:
            self._set_32bit(idx, value)

    def get_reg(self, idx: int, size: int) -> int:
        if size == 1:
            return self._get_8bit(idx)
        elif size == 2:
            return self._get_16bit(idx)
        else:
            return self._get_32bit(idx)

    @staticmethod
    def sreg_name(idx: int) -> str:
        return ["es", "cs", "ss", "ds", "fs", "gs"][idx]

    def set_sreg(self, idx: int, value: int) -> None:
        if value < 0:
            self.halt("sreg negative")
        if idx == 0:
            self.es = value & 0xFFFF
        elif idx == 1:
            self.cs = value & 0xFFFF
        elif idx == 2:
            self.ss = value & 0xFFFF
        elif idx == 3:
            self.ds = value & 0xFFFF
        elif idx == 4:
            self.fs = value & 0xFFFF
        elif idx == 5:
            self.gs = value & 0xFFFF

    def get_sreg(self, idx: int) -> int:
        if idx == 0:
            return self.es
        elif idx == 1:
            return self.cs
        elif idx == 2:
            return self.ss
        elif idx == 3:
            return self.ds
        elif idx == 4:
            return self.fs
        elif idx == 5:
            return self.gs
        self.halt(f"invalid sreg id {idx}")
        return 0

    def _set_16bit(self, idx: int, val: int) -> None:
        if idx == 0:
            self.eax = (self.eax & 0xFFFF0000) | (val & 0xFFFF)
        elif idx == 1:
            self.ecx = (self.ecx & 0xFFFF0000) | (val & 0xFFFF)
        elif idx == 2:
            self.edx = (self.edx & 0xFFFF0000) | (val & 0xFFFF)
        elif idx == 3:
            self.ebx = (self.ebx & 0xFFFF0000) | (val & 0xFFFF)
        elif idx == 4:
            self.esp = (self.esp & 0xFFFF0000) | (val & 0xFFFF)
        elif idx == 5:
            self.ebp = (self.ebp & 0xFFFF0000) | (val & 0xFFFF)
        elif idx == 6:
            self.esi = (self.esi & 0xFFFF0000) | (val & 0xFFFF)
        elif idx == 7:
            self.edi = (self.edi & 0xFFFF0000) | (val & 0xFFFF)

    def _set_8bit(self, idx: int, val: int) -> None:
        if idx == 0:
            self.eax = (self.eax & 0xFFFFFF00) | (val & 0xFF)
        elif idx == 1:
            self.ecx = (self.ecx & 0xFFFFFF00) | (val & 0xFF)
        elif idx == 2:
            self.edx = (self.edx & 0xFFFFFF00) | (val & 0xFF)
        elif idx == 3:
            self.ebx = (self.ebx & 0xFFFFFF00) | (val & 0xFF)
        elif idx == 4:
            self.eax = (self.eax & 0xFFFF00FF) | ((val & 0xFF) << 8)
        elif idx == 5:
            self.ecx = (self.ecx & 0xFFFF00FF) | ((val & 0xFF) << 8)
        elif idx == 6:
            self.edx = (self.edx & 0xFFFF00FF) | ((val & 0xFF) << 8)
        elif idx == 7:
            self.ebx = (self.ebx & 0xFFFF00FF) | ((val & 0xFF) << 8)

    def _set_32bit(self, idx: int, val: int) -> None:
        match idx:
            case 0:
                self.eax = val
            case 1:
                self.ecx = val
            case 2:
                self.edx = val
            case 3:
                self.ebx = val
            case 4:
                self.esp = val
            case 5:
                self.ebp = val
            case 6:
                self.esi = val
            case 7:
                self.edi = val

    def _get_16bit(self, idx: int) -> int:
        match idx:
            case 0:
                return self.eax & 0xFFFF
            case 1:
                return self.ecx & 0xFFFF
            case 2:
                return self.edx & 0xFFFF
            case 3:
                return self.ebx & 0xFFFF
            case 4:
                return self.esp & 0xFFFF
            case 5:
                return self.ebp & 0xFFFF
            case 6:
                return self.esi & 0xFFFF
            case 7:
                return self.edi & 0xFFFF
            case _:
                self.halt(f"unknown register {idx}")
                return 0

    def _get_8bit(self, idx: int) -> int:
        match idx:
            case 0:
                return self.eax & 0xFF
            case 1:
                return self.ecx & 0xFF
            case 2:
                return self.edx & 0xFF
            case 3:
                return self.ebx & 0xFF
            case 4:
                return (self.eax >> 8) & 0xFF
            case 5:
                return (self.ecx >> 8) & 0xFF
            case 6:
                return (self.edx >> 8) & 0xFF
            case 7:
                return (self.ebx >> 8) & 0xFF
            case _:
                self.halt(f"unknown register {idx}")
                return 0

    def _get_32bit(self, idx: int) -> int:
        return [self.eax, self.ecx, self.edx, self.ebx,
                self.esp, self.ebp, self.esi, self.edi][idx]

    @staticmethod
    def reg_name(idx: int, size: int = 4) -> str:
        return reg_names[size][idx]

    def resolve_address(self, segment: int, offset: int, override: bool = True) -> int:
        if override and self.segment_override:
            segment = self.segment_override
        if self.real_mode:
            return (segment * 16) + offset  # Real mode: segment * 16 + offset
        else:
            # Flat protected mode: segments are ignored unless paging/segmentation is used
            # For now, return just the offset (flat model)
            return offset

    def read_modrm(self, modrm: ModRM, size: int = None) -> int:
        if not size: size = self.size
        if modrm.mod == 0b11:
            return self.get_reg(modrm.rm, size)  # register direct
        else:
            return int.from_bytes(self.memory.read(modrm.addr, size), byteorder="little")

    def fetch(self, offset: int = 0, size: int = 1) -> bytes:
        addr = self.resolve_address(self.cs, self.ip + offset, False)
        return self.memory.read(addr, size)

    def get_size(self) -> None:
        self.address_size = 2 if self.real_mode ^ self.address_size_override else 4
        self.size = 2 if self.real_mode ^ self.size_override else 4

    def get_flag(self, flag: int) -> int:
        return (self.flags >> flag) & 1

    @staticmethod
    def _mask_for_size(size: int):
        return (1 << (size * 8)) - 1

    def set_flags_logic(self, result: int, size: int = 0):
        if not size: size = self.size
        mask = self._mask_for_size(size)
        res = result & mask
        # OF and CF cleared for logical ops
        self.set_flag(11, 0)  # OF
        self.set_flag(0, 0)  # CF
        self.set_flag(7, (res >> (size * 8 - 1)) & 1)  # SF
        self.set_flag(6, res == 0)  # ZF
        self.set_flag(4, 0)  # AF - omit/zero for now
        self.set_flag(2, bin(res & 0xFF).count("1") % 2 == 0)  # PF

    def set_flags_add(self, op1: int, op2: int, size: int = 0, carry_in: int = 0):
        if not size: size = self.size
        op2 += carry_in * self.get_flag(0)
        result = op1 + op2
        mask = self._mask_for_size(size)
        bits = size * 8
        res = result & mask
        # Carry if result truncated (unsigned overflow)
        self.set_flag(0, 1 if (result & ~mask) != 0 else 0)
        # Overflow if sign of operands same and sign differs from result
        sign_mask = 1 << (bits - 1)
        op1s = (op1 & sign_mask) != 0
        op2s = (op2 & sign_mask) != 0
        ress = (res & sign_mask) != 0
        self.set_flag(11, 1 if (op1s == op2s and ress != op1s) else 0)
        self.set_flag(7, 1 if ress else 0)  # SF
        self.set_flag(6, 1 if res == 0 else 0)  # ZF
        self.set_flag(4, 0)  # AF omitted/simplified
        self.set_flag(2, bin(res & 0xFF).count("1") % 2 == 0)  # PF

    def set_flags_sub(self, op1: int, op2: int, size: int = 0, borrow_in: int = 0):
        if not size: size = self.size
        op2 += borrow_in * self.get_flag(0)
        result = op1 - op2
        mask = self._mask_for_size(size)
        bits = size * 8
        res = result & mask
        # Carry for subtraction: borrow occurred => op1 < (op2 + borrow)
        self.set_flag(0, 1 if (op1 & mask) < ((op2 & mask) + borrow_in) else 0)
        # Overflow: op1 and op2 have different signs and result sign differs from op1 sign
        sign_mask = 1 << (bits - 1)
        op1s = (op1 & sign_mask) != 0
        op2s = (op2 & sign_mask) != 0
        ress = (res & sign_mask) != 0
        self.set_flag(11, 1 if (op1s != op2s and ress != op1s) else 0)
        self.set_flag(7, 1 if ress else 0)
        self.set_flag(6, 1 if res == 0 else 0)
        self.set_flag(4, 0)
        self.set_flag(2, bin(res & 0xFF).count("1") % 2 == 0)

    def set_flag(self, flag: int, value: int) -> None:
        if value:
            self.flags |= (1 << flag)
        else:
            self.flags &= ~(1 << flag)

    @staticmethod
    def halt(error_message: str = 'Halting CPU execution') -> None:
        print(error_message)
        exit()

    def log(self, message: str) -> None:
        if self.debug_mode:
            print(f"[CPU] {message}")
        return
