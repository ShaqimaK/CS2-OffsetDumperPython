from re import search

from pymem import Pymem
from datetime import datetime

from dumper.util import Operation
from ctypes import Structure, c_uint16, c_uint32, c_int32, sizeof


def debugPrint(text, start="", end="\n"):
    time = datetime.now()
    print("%s[%02.i:%02.i:%02.i.%06i] %s" % (start, time.hour, time.minute, time.second, time.microsecond, " ".join(text) if type(text) == list or type(text) == tuple else str(text)), end=end)



cs2 = Pymem("cs2.exe")
modules = {module.name: module for module in cs2.list_modules()}
client = modules.get("client.dll")



export_directory_start = client.lpBaseOfDll
export_directory_end = client.lpBaseOfDll + client.SizeOfImage
export_directory_size = client.SizeOfImage

print(export_directory_start, export_directory_end, export_directory_size)

buffer = cs2.read_bytes(client.lpBaseOfDll, client.SizeOfImage)

a = buffer.find(rb"CreateInterface")
print(a)

#b = buffer.find((search(rb'CreateInterface', buffer).start()).to_bytes(4, "little"))
#print(b)

print(cs2.read_int(client.lpBaseOfDll + a + 0xC))
