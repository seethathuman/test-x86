class Disk:
    def __init__(self, file):
        with open(file, 'br') as f:
            self.content: bytearray = bytearray(f.read())
        self.length: int = len(self.content)

    def read(self, start:int, count:int):
        return self.content[start % self.length:count + start % self.length]

    def write(self, start:int, data:bytearray) -> None:
        self.content[start:start + len(data)] = data

    def __len__(self) -> int:
        return self.length

    def __getitem__(self, item) -> bytearray:
        return self.content[item]

    def __setitem__(self, key, value) -> None:
        self.content[key] = value
