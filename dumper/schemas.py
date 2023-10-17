from pymem import Pymem
from util import Operation, debugPrint


from typing import Union
from json import dumps


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


def getModulesAddress(schemaSystemAddress: Union[int, hex]) -> list:
    moduleCount = cs2.read_uint(schemaSystemAddress + 0x190)
    moduleBaseAddress = cs2.read_ulonglong(schemaSystemAddress + 0x198)
    return [cs2.read_ulonglong(moduleBaseAddress + moduleIndex * 0x08) for moduleIndex in range(moduleCount)]


cs2 = Pymem("cs2.exe")
modules = {module.name: module for module in cs2.list_modules()}


schemaSystemAddress = cs2.pattern_scan_module(
    rb"".join([rb"\x" + i.encode() if i != "?" else rb"." for i in "48 8D 0D ? ? ? ? E9 ? ? ? ? CC CC CC CC 48 8D 0D ? ? ? ? E9 ? ? ? ? CC CC CC CC 48 83 EC 28".split(" ")]),
    modules.get("schemasystem.dll")
)
schemaSystemAddress = Operation.ripRelative(cs2, schemaSystemAddress)
modulesAddress = getModulesAddress(schemaSystemAddress)


schema = dict()
for moduleAddress in modulesAddress:
    module: RecvModule = RecvModule(moduleAddress)
    moduleName = module.name()
    debugPrint("【Schema】【%s】" % moduleName)

    moduleEntryMemory = module.entryMemory()
    moduleBucket = module.bucket()

    schema.update({moduleName: dict()})






    tableBaseAddress = moduleBucket.get("unallocatedData")
    tableBaseAddresses = list()
    while tableBaseAddress:
        tableBaseAddresses.append(tableBaseAddress)
        tableBaseAddress = module.tableNext(tableBaseAddress)
        #if not tableBaseAddress: break

    #debugPrint("———— tableBaseAddress: %s" % " -> ".join(["%s (%i)" % (hex(tableBaseAddress).upper().replace("X", "x"), tableBaseAddress) for tableBaseAddress in tableBaseAddresses]))
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

            schema[moduleName].update({tableName: dict()})

            #Prop Dump
            propCount = table.propCount()
            for propIndex in range(propCount):
                try:
                    prop = table.prop(propIndex)
                    if prop is None: continue

                    propName = prop.name()
                    propValue = prop.value()

                    schema[moduleName][tableName].update({propName: propValue})
                except Exception: break

            if tableCounter >= moduleEntryMemory.get("blockAllocatedSize"): break

        debugPrint("———— tableBaseAddress: %s (%i)" % (hex(tableBaseAddress).upper().replace("X", "x"), tableBaseAddress))
        #debugPrint("———— tableCount: %i" % (tableIndex + 1))
        if tableCounter >= moduleEntryMemory.get("blockAllocatedSize"): break


    debugPrint("———— TableCountTotal: %i" % len(schema[moduleName].keys()))
    debugPrint("———— PropCountTotal: %i" % len([ii for i in [tuple(schema[moduleName][tableName].keys()) for tableName in schema[moduleName].keys()] for ii in i]))

#print(dumps(schema, indent=4))
