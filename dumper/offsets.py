from pymem import Pymem, process
from pymem.ressources.structure import MODULEINFO
from re import search
from json import loads


from typing import Union
from inspect import signature as inspectSignature

from util import Operation, debugPrint
from requests import get





cs2 = Pymem("cs2.exe")
modules = {module.name: module for module in cs2.list_modules()}

"""
for moduleName, module in modules.items():
    debugPrint("【Module】【%s】" % moduleName)
    debugPrint("———— SizeOfImage: %s (%i)" % (hex(module.SizeOfImage).upper().replace("X", "x"), module.SizeOfImage))
    debugPrint("———— LpBaseOfDll: %s (%i)" % (hex(module.lpBaseOfDll).upper().replace("X", "x"), module.lpBaseOfDll))
    #debugPrint("———— Location: %s" % module.filename)
"""

def getSignatureOld(modname, pattern, extra=0, offsets=None, relative=True, debug=None):
    offsets = [0, 0] if offsets is None else offsets
    module = process.module_from_name(cs2.process_handle, modname)
    sig = search(rb"".join([rb"\x" + i.encode() if i != "?" else rb"." for i in pattern.split(" ")]), cs2.read_bytes(module.lpBaseOfDll, module.SizeOfImage)).start()
    for offset in offsets: sig = cs2.read_int(
        (module.lpBaseOfDll if offsets.index(offset) == 0 else 0) + sig + offset) + extra
    if debug is not None:
        debugPrint("【%s】" % debug)
        debugPrint("———— %s (offsets: %s, extra: %s, relative: %s) -> %s (%s)" % (
        pattern, offsets, extra, relative, hex(sig).upper(), sig))
    return sig - (module.lpBaseOfDll if relative and len(offsets) > 0 else 0)


def getSignature(module: Union[str, MODULEINFO], pattern: str, operations: Union[list, tuple], name: str = "None") -> int:
    debugPrint("【Signature】【%s】" % name)
    operations = [] if operations is None else operations
    module = process.module_from_name(cs2.process_handle, module) if isinstance(module, str) else module

    address = cs2.pattern_scan_module(rb"".join([rb"\x" + i.encode() if i != "?" else rb"." for i in pattern.split(" ")]), module)
    debugPrint("———— PatternScan: %s (%s) -> %s (%i)" % (module.name, pattern, hex(address).upper().replace("X", "x"), address))

    for operation in operations:
        address = getattr(Operation, operation["type"])(cs2, address, **{key: value for key, value in operation.items() if key in [str(parameter) for parameter in inspectSignature(getattr(Operation, operation["type"])).parameters]})
        debugPrint("———— Operation: %s -> %s (%i)" % (operation["type"], hex(address).upper().replace("X", "x"), address))

    if address > module.lpBaseOfDll: address -= module.lpBaseOfDll

    debugPrint("———— FinalAddress -> %s (%i)" % (hex(address).upper().replace("X", "x"), address))
    return address


#config = loads(open("config.json", "r").read())
config = get("https://raw.githubusercontent.com/a2x/cs2-dumper/main/config.json").json()
for signature in config.get("signatures"):
    getSignature(signature.get("module"), signature.get("pattern"), signature.get("operations"), name=signature.get("name"))
