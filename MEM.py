class AddressSpace:
    def __init__(self):
        self.content = []

    def map(self, obj, address):
        if len(self.content) < len(obj) + address:
            self.content.extend([0x00] * ((len(obj) + address) - len(self.content)))
            print(f"[ADDRESSSPACE] map object of length {len(self.content)}")

        for i in range(len(obj)):
            self.content[i + address] = obj[i]

    def read(self, offset, length):
        return self.content[offset:offset+length]

    def write(self, offset, data):
        if len(self.content) < len(data) + offset:
            self.content.extend([0x00] * (len(self.content) - (len(data) + offset)))
        for i in range(len(data)):
            self.content[i + offset] = data[i]

    def __getitem__(self, item):
        return self.content[item]