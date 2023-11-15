from pymem import Pymem, process

from typing import Union
from dataclasses import dataclass

from CS2.utils import Operation, pattern2Byte, debugPrint



class Offset:
    @dataclass
    class RecvProp:
        name = 0x0
        value = 0x10
        typeA = 0x8
        typeB = 0x8

    @dataclass
    class RecvTable:
        name = 0x8
        propCount = 0x1C
        propAddressBase = 0x28
        propAddressIndex = 0x20

    @dataclass
    class RecvModule:
        name = 0x08
        entryMemory = 0x588
        entryMemoryIndex = 0x04
        bucket = 0x5B0
        bucketIndex = 0x08
        tableAddress = 0x20
        tableAddressIndex = 0x18

    @dataclass
    class schemaSystem:
        schemaSystemPattern = "48 89 05 ? ? ? ? 4C 8D 45"
        schemaSystemPattern = "48 8D 0D ? ? ? ? E9 ? ? ? ? CC CC CC CC 48 8D 0D ? ? ? ? E9 ? ? ? ? CC CC CC CC 48 83 EC 28"
        moduleCount = 0x190
        moduleBaseAddress = 0x198
        modulesAddressIndex = 0x8



class RecvProp:
    def __init__(self, cs2: Pymem, propAddress: Union[int, hex]):
        self.cs2 = cs2
        self.propAddress = propAddress
    def address(self) -> Union[int, hex]: return self.propAddress
    def name(self) -> str: return self.cs2.read_string(self.cs2.read_ulonglong(self.propAddress + Offset.RecvProp.name))
    def value(self) -> int: return self.cs2.read_uint(self.propAddress + Offset.RecvProp.value)
    def type(self) -> str: return self.cs2.read_string(self.cs2.read_ulonglong(self.cs2.read_ulonglong(self.propAddress + Offset.RecvProp.typeA) + Offset.RecvProp.typeB))

class RecvTable:
    def __init__(self, cs2: Pymem, tableAddress: Union[int, hex]):
        self.cs2 = cs2
        self.tableAddress = tableAddress
        self.propAddressBase = cs2.read_ulonglong(self.tableAddress + Offset.RecvTable.propAddressBase)
    def address(self) -> Union[int, hex]: return self.tableAddress
    def name(self) -> str: return self.cs2.read_string(self.cs2.read_ulonglong(self.tableAddress + Offset.RecvTable.name))
    def propCount(self) -> int: return self.cs2.read_uint(self.tableAddress + Offset.RecvTable.propCount)
    def prop(self, index: int) -> Union[RecvProp, None]:
        propAddress = self.propAddressBase + (index * Offset.RecvTable.propAddressIndex)
        return RecvProp(self.cs2, propAddress) if propAddress else None

class RecvModule:
    def __init__(self, cs2: Pymem, moduleAddress: Union[int, hex]):
        self.cs2 = cs2
        self.moduleAddress = moduleAddress
    def address(self) -> Union[int, hex]: return self.moduleAddress
    def name(self) -> str: return self.cs2.read_string(self.moduleAddress + Offset.RecvModule.name)
    def entryMemory(self) -> dict:
        blockSize, blocksPerBlob, growMode, blocksAllocated, blockAllocatedSize, peakAlloc = [self.cs2.read_uint(self.moduleAddress + Offset.RecvModule.entryMemory + Offset.RecvModule.entryMemoryIndex * i) for i in range(6)]
        return dict(
            blockSize=blockSize, blocksPerBlob=blocksPerBlob,
            growMode=growMode,
            blocksAllocated=blocksAllocated, blockAllocatedSize=blockAllocatedSize,
            peakAlloc=peakAlloc
        )
    def bucket(self) -> dict:
        allocatedData, unallocatedData = [self.cs2.read_ulonglong(self.moduleAddress + Offset.RecvModule.bucket + Offset.RecvModule.bucketIndex * i) for i in range(2)]
        return dict(
            allocatedData=allocatedData,
            unallocatedData=unallocatedData,
        )
    def tableCount(self, entryMemory: dict) -> int: return min(entryMemory["blocksPerBlob"], entryMemory["blockAllocatedSize"])
    def tableNext(self, tableBaseAddress: Union[int, hex]) -> Union[int, hex]: return self.cs2.read_ulonglong(tableBaseAddress)
    def table(self, tableBaseAddress: Union[int, hex], index: int) -> Union[RecvTable, None]:
        tableAddress = tableBaseAddress + Offset.RecvModule.tableAddress + Offset.RecvModule.tableAddressIndex * index
        return RecvTable(self.cs2, self.cs2.read_ulonglong(tableAddress)) if tableAddress else None


class Schemas:
    def __init__(self, cs2: Pymem): self.cs2 = cs2


    @classmethod
    def dump(cls, cs2: Pymem) -> dict:
        schemaSystemAddress = cs2.pattern_scan_module(pattern2Byte(Offset.schemaSystem.schemaSystemPattern), process.module_from_name(cs2.process_handle, "schemasystem.dll"))
        schemaSystemAddress = Operation.rip(cs2, schemaSystemAddress)

        moduleCount = cs2.read_uint(schemaSystemAddress + Offset.schemaSystem.moduleCount)
        moduleBaseAddress = cs2.read_ulonglong(schemaSystemAddress + Offset.schemaSystem.moduleBaseAddress)
        modulesAddress = [cs2.read_ulonglong(moduleBaseAddress + moduleIndex * Offset.schemaSystem.modulesAddressIndex) for moduleIndex in range(moduleCount)]

        modules = dict()
        for moduleAddress in modulesAddress:
            modules.update(cls.moduleDump(cs2, moduleAddress))

        return modules

    @classmethod
    def moduleDump(cls, cs2: Pymem, moduleAddress: Union[int, hex]) -> dict:
        module: RecvModule = RecvModule(cs2, moduleAddress)
        moduleName = module.name()
        debugPrint("【Schema】【%s】" % moduleName)

        moduleEntryMemory = module.entryMemory()
        moduleBucket = module.bucket()

        tableBaseAddress = moduleBucket.get("unallocatedData")
        tableBaseAddresses = list()
        while tableBaseAddress:
            tableBaseAddresses.append(tableBaseAddress)
            tableBaseAddress = module.tableNext(tableBaseAddress)
        debugPrint("———— TableBaseAddressCount: %s" % len(tableBaseAddresses))
        [debugPrint("———— TableBaseAddress: %s (%i)" % (hex(tableBaseAddress).upper().replace("X", "x"), tableBaseAddress)) for tableBaseAddress in tableBaseAddresses]

        tables = dict()
        tableCounter = 0
        tableCount = module.tableCount(moduleEntryMemory)
        for tableBaseAddress in tableBaseAddresses:
            if not tableBaseAddress: continue

            for tableIndex in range(tableCount):
                tableCounter += 1

                tables.update(cls.tableDump(module, tableBaseAddress, tableIndex))

                if tableCounter >= moduleEntryMemory.get("blockAllocatedSize"): break
            if tableCounter >= moduleEntryMemory.get("blockAllocatedSize"): break

        debugPrint("———— TableCountTotal: %i" % len(tables.keys()))
        debugPrint("———— PropCountTotal: %i" % len([prop for table in tables.values() for prop in table]))
        #debugPrint("———— Schema: %s" % tables)
        return {moduleName: tables}

    @classmethod
    def tableDump(cls, module: RecvModule, tableBaseAddress: Union[int, hex], tableIndex: int) -> dict:
        table = module.table(tableBaseAddress, tableIndex)
        tableName = table.name()

        props = dict()
        propCount = table.propCount()
        for propIndex in range(propCount):
            try: props.update(cls.propDump(table, propIndex))
            except Exception: break

        return {tableName: props}

    @classmethod
    def propDump(cls, table: RecvTable, propIndex: int) -> dict:
        prop = table.prop(propIndex)

        if prop is None: return dict()

        propName = prop.name()
        propValue = prop.value()

        return {propName: propValue}

