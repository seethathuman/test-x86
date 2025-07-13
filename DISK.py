class Disk:
    def __init__(self, file):
        with open(file, 'br') as f:
            self.content = bytearray(f.read())
        self.length = len(self.content)

    def read(self, start, count):
        return self.content[start % self.length:count+start % self.length]

    def write(self, start, data):
        self.content[start:start+len(data)] = data

    def __len__(self):
        return self.length

    def __getitem__(self, item):
        return self.content[item]

    def __setitem__(self, key, value):
        if isinstance(value, bytes): value = value[0]
        self.content[key] = value