

__all__ = [
    "Operation",
    "pattern2Byte",
    "dict2Class",
    "infoPrinter",
]




def debugPrint(text, start="", end="\n"):
    from datetime import datetime

    time = datetime.now()
    print("%s[%02.i:%02.i:%02.i] %s" % (start, time.hour, time.minute, time.second, " ".join(text) if type(text) == list or type(text) == tuple else str(text)), end=end)


class Operation:
    from pymem import Pymem
    from typing import Union

    @classmethod
    def add(cls, cs2: Pymem, address: Union[int, hex], value: int = 0) -> Union[int, hex]:
        return address + value

    @classmethod
    def sub(cls, cs2: Pymem, address: Union[int, hex], value: int = 0) -> Union[int, hex]:
        return address - value

    @classmethod
    def offset(cls, cs2: Pymem, address: Union[int, hex], position: int = 0) -> Union[int, hex]:
        return cs2.read_uint(address + position)

    @classmethod
    def deref(cls, cs2: Pymem, address: Union[int, hex], times: int = 1, size: int = 8) -> Union[int, hex]:
        for _ in range(times): address = cs2.read_bytes(address, size)
        return int.from_bytes(address, byteorder="little")

    @classmethod
    def rip(cls, cs2: Pymem, address: Union[int, hex], offset: int = 3, length: int = 7) -> Union[int, hex]:
        displacement = cs2.read_int(address + offset)
        return address + length + displacement

    @classmethod
    def jmp(cls, cs2: Pymem, address: Union[int, hex], offset: int = 1, length: int = 5) -> Union[int, hex]:
        displacement = cs2.read_uint(address + offset)
        return address + length + displacement

    @classmethod
    def slice(cls, cs2: Pymem, address: Union[int, hex], start: int = 0, end: int = 0) -> Union[int, hex]:
        result = cs2.read_bytes(cls.add(cs2, address, start), end - start)
        return int.from_bytes(result, byteorder="little")


def pattern2Byte(pattern: str) -> bytes:
    return rb"".join([rb"." if "?" in byte else rb"\x" + byte.encode() for byte in pattern.split(" ")])

def dict2Class(data: dict) -> classmethod.__class__: return type("class", (), {**data, **{"__dict__": data}})()

def infoPrinter(name: str):
    from logging import getLogger, StreamHandler, Formatter

    handler = StreamHandler()
    handler.setFormatter(Formatter(" ".join((
        "\033[1;31m[INFO]\033[0m",
        "\033[1;32m[%(asctime)s]\033[0m",
        "\033[1;35m[%(filename)s:%(lineno)d]\033[0m",
        "\033[1;97m%(message)s\033[0m",
    ))))
    logger = getLogger(name)
    logger.addHandler(handler)
    logger.setLevel(20)

    return logger.info

