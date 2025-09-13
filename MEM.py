class Byte:
    def __init__(self, idx: int, mapped_object):
        self.idx: int = idx
        self.obj = mapped_object

    def value(self) -> int:
        return self.obj[self.idx]

    def set(self, value: int) -> None:
        self.obj[self.idx] = value


class Dummy:
    def __init__(self, message: str):
        self.message: str = message

    def value(self) -> None:
        raise KeyError(f"Attempt to read uninitialized memory {self.message}")

    def set(self, address=0) -> None:
        raise KeyError(f"Attempt to write to uninitialized memory {self.message}")


class AddressSpace:
    def __init__(self):
        self.content: list[Byte | Dummy] = []

    def map(self, address: int, obj) -> None:
        if len(self.content) < len(obj) + address:
            self.content.extend([Dummy(f"from {hex(len(self.content))} to {hex(address)}")] * (
                    (len(obj) + address) - len(self.content)))
            print(f"[ADDRESSSPACE] map object of length {len(self.content)}")
        for i in range(len(obj)):
            self.content[i + address] = Byte(i, obj)

    def read(self, offset: int, length: int) -> bytes:
        return bytes([byte.value() for byte in self.content[offset:offset + length]])

    def write(self, offset: int, data: bytearray | bytes) -> None:
        for i, b in enumerate(data):
            self.content[offset + i].set(b)

    def __getitem__(self, item):
        print("[ADDRESSSPACE] WARNING: direct read to memory, please use read() instead.")
        return self.content[item]
