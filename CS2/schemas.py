from pymem import Pymem, process

from typing import Union
from json import dumps

from CS2.utils import Operation, patternConvert2Byte, debugPrint



class RecvProp:
    def __init__(self, cs2: Pymem, propAddress: Union[int, hex]):
        self.cs2 = cs2
        self.propAddress = propAddress
    def address(self) -> Union[int, hex]: return self.propAddress
    def name(self) -> str: return self.cs2.read_string(self.cs2.read_ulonglong(self.propAddress))
    def value(self) -> int: return self.cs2.read_uint(self.propAddress + 0x10)
    def type(self) -> str: return self.cs2.read_string(self.cs2.read_ulonglong(self.cs2.read_ulonglong(self.propAddress + 0x8) + 0x8))

class RecvTable:
    def __init__(self, cs2: Pymem, tableAddress: Union[int, hex]):
        self.cs2 = cs2
        self.tableAddress = tableAddress
        self.propAddressBase = cs2.read_ulonglong(self.tableAddress + 0x28)
    def address(self) -> Union[int, hex]: return self.tableAddress
    def name(self) -> str: return self.cs2.read_string(self.cs2.read_ulonglong(self.tableAddress + 0x8))
    def propCount(self) -> int: return self.cs2.read_uint(self.tableAddress + 0x1C)
    def prop(self, index: int) -> Union[RecvProp, None]:
        propAddress = self.propAddressBase + (index * 0x20)
        return RecvProp(self.cs2, propAddress) if propAddress else None

class RecvModule:
    def __init__(self, cs2: Pymem, moduleAddress: Union[int, hex]):
        self.cs2 = cs2
        self.moduleAddress = moduleAddress
    def address(self) -> Union[int, hex]: return self.moduleAddress
    def name(self) -> str: return self.cs2.read_string(self.moduleAddress + 0x08)
    def entryMemory(self) -> dict:
        blockSize, blocksPerBlob, growMode, blocksAllocated, blockAllocatedSize, peakAlloc = [self.cs2.read_uint(self.moduleAddress + 0x588 + 0x04 * i) for i in range(6)]
        return dict(
            blockSize=blockSize, blocksPerBlob=blocksPerBlob,
            growMode=growMode,
            blocksAllocated=blocksAllocated, blockAllocatedSize=blockAllocatedSize,
            peakAlloc=peakAlloc
        )
    def bucket(self) -> dict:
        allocatedData, unallocatedData = [self.cs2.read_ulonglong(self.moduleAddress + 0x5B0 + 0x08 * i) for i in range(2)]
        return dict(
            allocatedData=allocatedData,
            unallocatedData=unallocatedData,
        )
    def tableCount(self, entryMemory: dict) -> int: return min(entryMemory["blocksPerBlob"], entryMemory["blockAllocatedSize"])
    def tableNext(self, tableBaseAddress: Union[int, hex]) -> Union[int, hex]: return self.cs2.read_ulonglong(tableBaseAddress)
    def table(self, tableBaseAddress: Union[int, hex], index: int) -> Union[RecvTable, None]:
        tableAddress = tableBaseAddress + 0x20 + 0x18 * index
        return RecvTable(self.cs2, self.cs2.read_ulonglong(tableAddress)) if tableAddress else None


class Schemas:
    def __init__(self, cs2: Pymem):
        self.cs2 = cs2


    def schemaDump(self) -> dict:
        schemaSystemAddress = self.cs2.pattern_scan_module(patternConvert2Byte("48 8D 0D ? ? ? ? E9 ? ? ? ? CC CC CC CC 48 8D 0D ? ? ? ? E9 ? ? ? ? CC CC CC CC 48 83 EC 28"), process.module_from_name(self.cs2.process_handle, "schemasystem.dll"))
        schemaSystemAddress = Operation.ripRelative(self.cs2, schemaSystemAddress)

        moduleCount = self.cs2.read_uint(schemaSystemAddress + 0x190)
        moduleBaseAddress = self.cs2.read_ulonglong(schemaSystemAddress + 0x198)
        modulesAddress = [self.cs2.read_ulonglong(moduleBaseAddress + moduleIndex * 0x08) for moduleIndex in range(moduleCount)]

        modules = dict()
        for moduleAddress in modulesAddress:
            modules.update(self.moduleDump(moduleAddress))

        return modules



    def moduleDump(self, moduleAddress: Union[int, hex]) -> dict:
        module: RecvModule = RecvModule(self.cs2, moduleAddress)
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

                tables.update(self.tableDump(module, tableBaseAddress, tableIndex))

                if tableCounter >= moduleEntryMemory.get("blockAllocatedSize"): break
            if tableCounter >= moduleEntryMemory.get("blockAllocatedSize"): break

        debugPrint("———— TableCountTotal: %i" % len(tables.keys()))
        debugPrint("———— PropCountTotal: %i" % len([prop for table in tables.values() for prop in table]))
        #debugPrint("———— Schema: %s" % tables)
        return {moduleName: tables}



    def tableDump(self, module: RecvModule, tableBaseAddress: Union[int, hex], tableIndex: int) -> dict:
        table = module.table(tableBaseAddress, tableIndex)
        tableName = table.name()

        props = dict()
        propCount = table.propCount()
        for propIndex in range(propCount):
            try: props.update(self.propDump(table, propIndex))
            except Exception: break

        return {tableName: props}


    def propDump(self, table: RecvTable, propIndex: int) -> dict:
        prop = table.prop(propIndex)

        if prop is None: return dict()

        propName = prop.name()
        propValue = prop.value()

        return {propName: propValue}

