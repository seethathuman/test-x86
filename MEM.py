class Byte:
    def __init__(self, idx: int, mapped_object):
        self.idx = idx
        self.obj = mapped_object

        if not isinstance(self.idx, int): raise TypeError("index must be integer")

    def value(self) -> bytes:
        return self.obj[self.idx].to_bytes()

    def set(self, value: bytes):
        if not isinstance(value, bytes): raise TypeError("mapped byte must be set to byte")
        self.obj[self.idx] = value

class AddressSpace:
    def __init__(self):
        self.content: list[bytes | Byte] = []

    def map(self, address: int, obj) -> None:
        if len(self.content) < len(obj) + address:
            self.content.extend([b"\x00"] * ((len(obj) + address) - len(self.content)))
            print(f"[ADDRESSSPACE] map object of length {len(self.content)}")
        for i in range(len(obj)):
            self.content[i + address] = Byte(i, obj)

    def read(self, offset: int, length: int) -> bytearray:
        content = bytearray()
        for offset in range(offset, offset+length):
            byte = self.content[offset]
            if isinstance(byte, Byte): byte = byte.value()
            content += byte
        return content

    def write(self, offset: int, data: bytearray | bytes) -> None:
        if isinstance(data, bytes):
            data: bytearray = bytearray(data)
        if len(self.content) < len(data) + offset:
            self.content.extend([b"\x00"] * ((len(data) + offset) - len(self.content)))
        for i in range(len(data)):
            byte = self.content[i + offset]
            if isinstance(byte, Byte): byte.set(data[i].to_bytes())
            else: self.content[i + offset] = data[i].to_bytes()

    def __getitem__(self, item):
        return self.content[item]