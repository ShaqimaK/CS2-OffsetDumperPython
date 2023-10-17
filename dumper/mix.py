from pymem import Pymem, process
from pymem.ressources.structure import MODULEINFO

from typing import Union
from inspect import signature as inspectSignature

from requests import get



from datetime import datetime
def debugPrint(text, start="", end="\n"):
    time = datetime.now()
    print("%s[%02.i:%02.i:%02.i] %s" % (start, time.hour, time.minute, time.second, " ".join(text) if type(text) == list or type(text) == tuple else str(text)), end=end)


class Operation:
    @classmethod
    def add(cls, address, value=0):
        return address + value

    @classmethod
    def subtract(cls, address, value=0):
        return address - value

    @classmethod
    def offset(cls, address, position=0):
        return cs2.read_uint(address + position)

    @classmethod
    def dereference(cls, address, times=1, size=8):
        for _ in range(times): address = cs2.read_bytes(address, size)
        return int.from_bytes(address, byteorder="little")

    @classmethod
    def ripRelative(cls, address, offset=0x3, length=0x7):
        displacement = cs2.read_int(address + offset)
        return address + length + displacement

    @classmethod
    def jmp(cls, address, offset=0x1, length=0x5):
        displacement = cs2.read_uint(address + offset)
        return address + length + displacement

    @classmethod
    def slice(cls, address, start=0, end=0):
        result = cs2.read_bytes(cls.add(address, start), end - start)
        return int.from_bytes(result, byteorder="little")


def getSignature(module: Union[str, MODULEINFO], pattern: str, operations: Union[list, tuple], name: str = "None") -> int:
    debugPrint("【Signature】【%s】" % name)
    operations = [] if operations is None else operations
    module = process.module_from_name(cs2.process_handle, module) if isinstance(module, str) else module

    address = cs2.pattern_scan_module(rb"".join([rb"\x" + i.encode() if i != "?" else rb"." for i in pattern.split(" ")]), module)
    debugPrint("———— PatternScan: %s (%s) -> %s (%i)" % (module.name, pattern, hex(address).upper().replace("X", "x"), address))

    for operation in operations:
        address = getattr(Operation, operation["type"])(address, **{key: value for key, value in operation.items() if key in [str(parameter) for parameter in inspectSignature(getattr(Operation, operation["type"])).parameters]})
        debugPrint("———— Operation: %s -> %s (%i)" % (operation["type"], hex(address).upper().replace("X", "x"), address))

    if address > module.lpBaseOfDll: address -= module.lpBaseOfDll

    debugPrint("———— FinalAddress -> %s (%i)" % (hex(address).upper().replace("X", "x"), address))
    return address


def getModulesAddress(schemaSystemAddress: Union[int, hex]) -> list:
    moduleCount = cs2.read_uint(schemaSystemAddress + 0x190)
    moduleBaseAddress = cs2.read_ulonglong(schemaSystemAddress + 0x198)
    return [cs2.read_ulonglong(moduleBaseAddress + moduleIndex * 0x08) for moduleIndex in range(moduleCount)]

class RecvProp:
    def __init__(self, propAddress: Union[int, hex]):
        self.propAddress = propAddress
    def address(self) -> Union[int, hex]: return self.propAddress
    def name(self) -> str: return cs2.read_string(cs2.read_ulonglong(self.propAddress))
    def value(self) -> int: return cs2.read_uint(self.propAddress + 0x10)
    def type(self) -> str: return cs2.read_string(cs2.read_ulonglong(cs2.read_ulonglong(self.propAddress + 0x8) + 0x8))

class RecvTable:
    def __init__(self, tableAddress: Union[int, hex]):
        self.tableAddress = tableAddress
        self.propAddressBase = cs2.read_ulonglong(self.tableAddress + 0x28)
    def address(self) -> Union[int, hex]: return self.tableAddress
    def name(self) -> str: return cs2.read_string(cs2.read_ulonglong(self.tableAddress + 0x8))
    def propCount(self) -> int: return cs2.read_uint(self.tableAddress + 0x1C)
    def prop(self, index: int) -> Union[RecvProp, None]:
        propAddress = self.propAddressBase + (index * 0x20)
        return RecvProp(propAddress) if propAddress else None

class RecvModule:
    def __init__(self, moduleAddress: Union[int, hex]):
        self.moduleAddress = moduleAddress
    def address(self) -> Union[int, hex]: return self.moduleAddress
    def name(self) -> str: return cs2.read_string(self.moduleAddress + 0x08)
    def entryMemory(self) -> dict:
        blockSize, blocksPerBlob, growMode, blocksAllocated, blockAllocatedSize, peakAlloc = [cs2.read_uint(self.moduleAddress + 0x588 + 0x04 * i) for i in range(6)]
        return dict(
            blockSize=blockSize, blocksPerBlob=blocksPerBlob,
            growMode=growMode,
            blocksAllocated=blocksAllocated, blockAllocatedSize=blockAllocatedSize,
            peakAlloc=peakAlloc
        )
    def bucket(self) -> dict:
        allocatedData, unallocatedData = [cs2.read_ulonglong(self.moduleAddress + 0x5B0 + 0x08 * i) for i in range(2)]
        return dict(
            allocatedData=allocatedData,
            unallocatedData=unallocatedData,
        )
    def tableCount(self, entryMemory: dict) -> int: return min(entryMemory["blocksPerBlob"], entryMemory["blockAllocatedSize"])
    def tableNext(self, tableBaseAddress: Union[int, hex]) -> Union[int, hex]: return cs2.read_ulonglong(tableBaseAddress)
    def table(self, tableBaseAddress: Union[int, hex], index: int) -> Union[RecvTable, None]:
        tableAddress = tableBaseAddress + 0x20 + 0x18 * index
        return RecvTable(cs2.read_ulonglong(tableAddress)) if tableAddress else None



cs2 = Pymem("cs2.exe")
modules = {module.name: module for module in cs2.list_modules()}

# Signatures Dump
signatures = dict()
for signature in get("https://raw.githubusercontent.com/a2x/cs2-dumper/main/config.json").json().get("signatures"):
    signatures.update({signature.get("name"): getSignature(signature.get("module"), signature.get("pattern"), signature.get("operations"), name=signature.get("name"))})



# Schema Dump
schemaSystemAddress = cs2.pattern_scan_module(
    rb"".join([rb"\x" + i.encode() if i != "?" else rb"." for i in "48 8D 0D ? ? ? ? E9 ? ? ? ? CC CC CC CC 48 8D 0D ? ? ? ? E9 ? ? ? ? CC CC CC CC 48 83 EC 28".split(" ")]),
    modules.get("schemasystem.dll")
)
schemaSystemAddress = Operation.ripRelative(schemaSystemAddress)
modulesAddress = getModulesAddress(schemaSystemAddress)

schemas = dict()
for moduleAddress in modulesAddress:
    module: RecvModule = RecvModule(moduleAddress)
    moduleName = module.name()
    debugPrint("【Schema】【%s】" % moduleName)

    moduleEntryMemory = module.entryMemory()
    moduleBucket = module.bucket()

    schemas.update({moduleName: dict()})


    tableBaseAddress = moduleBucket.get("unallocatedData")
    tableBaseAddresses = list()
    while tableBaseAddress:
        tableBaseAddresses.append(tableBaseAddress)
        tableBaseAddress = module.tableNext(tableBaseAddress)
        # if not tableBaseAddress: break

    # debugPrint("———— tableBaseAddress: %s" % " -> ".join(["%s (%i)" % (hex(tableBaseAddress).upper().replace("X", "x"), tableBaseAddress) for tableBaseAddress in tableBaseAddresses]))
    debugPrint("———— tableBaseAddressCount: %s" % len(tableBaseAddresses))


    # Table Dump
    tableCounter = 0
    tableCount = module.tableCount(moduleEntryMemory)
    for tableBaseAddress in tableBaseAddresses:
        if not tableBaseAddress: continue

        for tableIndex in range(tableCount):
            tableCounter += 1

            table = module.table(tableBaseAddress, tableIndex)
            tableName = table.name()

            schemas[moduleName].update({tableName: dict()})

            # Prop Dump
            propCount = table.propCount()
            for propIndex in range(propCount):
                try:
                    prop = table.prop(propIndex)
                    if prop is None: continue

                    propName = prop.name()
                    propValue = prop.value()

                    schemas[moduleName][tableName].update({propName: propValue})
                except Exception: break

            if tableCounter >= moduleEntryMemory.get("blockAllocatedSize"): break

        debugPrint(
            "———— tableBaseAddress: %s (%i)" % (hex(tableBaseAddress).upper().replace("X", "x"), tableBaseAddress))
        # debugPrint("———— tableCount: %i" % (tableIndex + 1))
        if tableCounter >= moduleEntryMemory.get("blockAllocatedSize"): break

    debugPrint("———— TableCountTotal: %i" % len(schemas[moduleName].keys()))
    debugPrint("———— PropCountTotal: %i" % len([ii for i in [tuple(schemas[moduleName][tableName].keys()) for tableName in schemas[moduleName].keys()] for ii in i]))

from json import dumps
print(dumps(signatures, indent=4))
print(dumps(schemas, indent=4))


