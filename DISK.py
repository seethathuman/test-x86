class Disk:
    def __init__(self):
        with open('dos.img', 'br') as f:
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
        self.content[key] = value