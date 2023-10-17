from pymem import Pymem

class Operation:
    @classmethod
    def add(cls, cs2: Pymem, address, value=0):
        return address + value

    @classmethod
    def subtract(cls, cs2: Pymem, address, value=0):
        return address - value

    @classmethod
    def offset(cls, cs2: Pymem, address, position=0):
        return cs2.read_uint(address + position)

    @classmethod
    def dereference(cls, cs2: Pymem, address, times=1, size=8):  # BUG
        for _ in range(times): address = cs2.read_bytes(address, size)
        return int.from_bytes(address, byteorder="little")

    @classmethod
    def ripRelative(cls, cs2: Pymem, address, offset=0x3, length=0x7):
        displacement = cs2.read_int(address + offset)
        return address + length + displacement

    @classmethod
    def jmp(cls, cs2: Pymem, address, offset=0x1, length=0x5):
        displacement = cs2.read_uint(address + offset)
        return address + length + displacement

    @classmethod
    def slice(cls, cs2: Pymem, address, start=0, end=0):
        result = cs2.read_bytes(cls.add(cs2, address, start), end - start)
        return int.from_bytes(result, byteorder="little")


from datetime import datetime
def debugPrint(text, start="", end="\n"):
    time = datetime.now()
    print("%s[%02.i:%02.i:%02.i] %s" % (start, time.hour, time.minute, time.second, " ".join(text) if type(text) == list or type(text) == tuple else str(text)), end=end)
