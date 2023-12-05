from pymem import Pymem, process
from CS2.utils import Operation, pattern2Byte, dict2Class, infoPrinter

from typing import Union
from dataclasses import dataclass

info = infoPrinter(__name__)



class Offset:
    class RecvField:
        name = 0x0
        value = 0x10
        typeA = 0x08
        typeB = 0x08

    class RecvTable:
        name = 0x08
        fieldCount = 0x1C
        fieldAddressBase = 0x28
        fieldAddressIndex = 0x20
        parentAddressA = 0x38
        parentAddressB = 0x08

    class RecvModule:
        name = 0x08
        memoryPool = 0x588
        memoryPoolIndex = 0x04
        bucket = 0x5B0
        bucketIndex = 0x08
        allocatedData = 0x5B0
        unallocatedData = 0x5B0 + 0x08
        tableAddress = 0x20
        tableAddressIndex = 0x18

    class schemaSystem:
        schemaSystemPattern = "48 89 05 ? ? ? ? 4C 8D 45"
        #schemaSystemPattern = "48 8D 0D ? ? ? ? E9 ? ? ? ? CC CC CC CC 48 8D 0D ? ? ? ? E9 ? ? ? ? CC CC CC CC 48 83 EC 28"
        moduleCount = 0x190
        moduleBaseAddress = 0x198
        modulesAddressIndex = 0x08



class RecvField:
    def __init__(self, cs2: Pymem, fieldAddress: Union[int, hex]):
        self.cs2 = cs2
        self.fieldAddress = fieldAddress
    def address(self) -> Union[int, hex]: return self.fieldAddress
    def metadata(self) -> Union[int, hex, None]:
        return metadataAddress if (metadataAddress := self.cs2.read_ulonglong(self.fieldAddress + 0x18)) else None
    def name(self) -> Union[str, None]:
        if not (nameAddress := self.cs2.read_ulonglong(self.fieldAddress + Offset.RecvField.name)): return "Error"
        return self.cs2.read_string(nameAddress)
    def value(self) -> int: return self.cs2.read_uint(self.fieldAddress + Offset.RecvField.value)
    def type(self) -> str: return self.cs2.read_string(self.cs2.read_ulonglong(self.cs2.read_ulonglong(self.fieldAddress + Offset.RecvField.typeA) + Offset.RecvField.typeB))


class RecvTable:
    def __init__(self, cs2: Pymem, tableAddress: Union[int, hex]):
        self.cs2 = cs2
        self.tableAddress = tableAddress
        self.fieldAddressBase = cs2.read_ulonglong(self.tableAddress + Offset.RecvTable.fieldAddressBase)
    def address(self) -> Union[int, hex]: return self.tableAddress
    def parent(self) -> Union[int, hex, None]:
        if not (parentAddress := self.cs2.read_ulonglong(self.tableAddress + Offset.RecvTable.parentAddressA)): return None
        if not (parentAddress := self.cs2.read_ulonglong(parentAddress + Offset.RecvTable.parentAddressB)): return None
        return RecvTable(self.cs2, parentAddress)
    def metadata(self) -> Union[int, hex, None]:
        return metadataAddress if (metadataAddress := self.cs2.read_ulonglong(self.tableAddress + 0x8)) else None
    def name(self) -> Union[str, None]:
        if not (nameAddress := self.cs2.read_ulonglong(self.tableAddress + Offset.RecvTable.name)): return "Error"
        return self.cs2.read_string(nameAddress)
    def fieldCount(self) -> int: return self.cs2.read_uint(self.tableAddress + Offset.RecvTable.fieldCount)
    def field(self, index: int) -> Union[RecvField, None]:
        if not (fieldAddress := self.fieldAddressBase + (index * Offset.RecvTable.fieldAddressIndex)): return None
        return RecvField(self.cs2, fieldAddress)

class RecvModule:
    def __init__(self, cs2: Pymem, moduleAddress: Union[int, hex]):
        self.cs2 = cs2
        self.moduleAddress = moduleAddress
    def address(self) -> Union[int, hex]: return self.moduleAddress
    def name(self) -> Union[str, None]: return name if (name := self.cs2.read_string(self.moduleAddress + Offset.RecvModule.name)) else "Error"
    def memoryPool(self) -> dict:
        blockSize, blocksPerBlob, growMode, blocksAllocated, blockAllocatedSize, peakAlloc = [self.cs2.read_uint(self.moduleAddress + Offset.RecvModule.memoryPool + Offset.RecvModule.memoryPoolIndex * i) for i in range(6)]
        return dict(
            blockSize=blockSize, blocksPerBlob=blocksPerBlob,
            growMode=growMode,
            blocksAllocated=blocksAllocated, blockAllocatedSize=blockAllocatedSize,
            peakAlloc=peakAlloc
        )
    def hashBucket(self) -> Union[dict, None]:
        #allocatedData, unallocatedData = [self.cs2.read_ulonglong(self.moduleAddress + Offset.RecvModule.bucket + Offset.RecvModule.bucketIndex * i) for i in range(2)]
        if not (allocatedData := self.cs2.read_ulonglong(self.moduleAddress + Offset.RecvModule.allocatedData)): return None
        if not (unallocatedData := self.cs2.read_ulonglong(self.moduleAddress + Offset.RecvModule.unallocatedData)): return None

        return dict(
            allocatedData=allocatedData, unallocatedData=unallocatedData
        )
    def tableCount(self, memoryPool: dict) -> int: return min(memoryPool["blocksPerBlob"], memoryPool["blockAllocatedSize"])
    def tableNext(self, tableBaseAddress: Union[int, hex]) -> Union[int, hex]: return self.cs2.read_ulonglong(tableBaseAddress)
    def table(self, tableBaseAddress: Union[int, hex], index: int) -> Union[RecvTable, None]:
        if not (tableAddress := tableBaseAddress + Offset.RecvModule.tableAddress + Offset.RecvModule.tableAddressIndex * index): return None
        return RecvTable(self.cs2, self.cs2.read_ulonglong(tableAddress))


class SchemaDump:
    def __init__(self, cs2: Pymem):
        self.cs2 = cs2


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
        info("【Schema】【%s】" % moduleName)

        if None in (
                (moduleMemoryPool := module.memoryPool()),
                (moduleHashBucket := module.hashBucket())
        ):
            info("———— Skipped: MemoryPool or HashBucket is None")
            info("———— MemoryPool：%s" % moduleMemoryPool)
            info("———— HashBucket: %s" % moduleHashBucket)
            return {moduleName: dict()}
        moduleMemoryPool = dict2Class(moduleMemoryPool)
        moduleHashBucket = dict2Class(moduleHashBucket)


        tableBaseAddress = moduleHashBucket.unallocatedData
        tableBaseAddresses = list()
        while tableBaseAddress:
            tableBaseAddresses.append(tableBaseAddress)
            tableBaseAddress = module.tableNext(tableBaseAddress)
        info("———— TableBaseAddressCount: %s" % len(tableBaseAddresses))
        #[info("———— TableBaseAddress (%i): %s (%i)" % (tableBaseAddresses.index(tableBaseAddress) + 1, hex(tableBaseAddress).upper().replace("X", "x"), tableBaseAddress)) for tableBaseAddress in tableBaseAddresses]

        tables = dict()
        tableCounter = 0
        tableCount = module.tableCount(moduleMemoryPool.__dict__)
        for tableBaseAddress in tableBaseAddresses:
            if not tableBaseAddress: continue
            info("———— (%i/%i) TableBaseAddress: %s (%i)" % (tableBaseAddresses.index(tableBaseAddress) + 1, len(tableBaseAddresses), hex(tableBaseAddress).upper().replace("X", "x"), tableBaseAddress))

            tablesCache = tables.copy()
            for tableIndex in range(tableCount):
                tableCounter += 1
                tables.update(cls.tableDump(cs2, module, tableBaseAddress, tableIndex))

                if tableCounter >= moduleMemoryPool.blockAllocatedSize: break

            info("———— (%i/%i) TableCount: %i" % (tableBaseAddresses.index(tableBaseAddress) + 1, len(tableBaseAddresses), len(tables.keys()) - len(tablesCache.keys())))
            info("———— (%i/%i) FieldCount: %i" % (tableBaseAddresses.index(tableBaseAddress) + 1, len(tableBaseAddresses), len([field for table in tables.values() for field in table]) - len([field for table in tablesCache.values() for field in table])))
            if tableCounter >= moduleMemoryPool.blockAllocatedSize: break

        info("———— TableCountTotal: %i" % len(tables.keys()))
        info("———— FieldCountTotal: %i" % len([field for table in tables.values() for field in table]))
        #debugPrint("———— Schema: %s" % tables)
        return {moduleName: tables}

    @classmethod
    def tableDump(cls, cs2: Pymem, module: RecvModule, tableBaseAddress: Union[int, hex], tableIndex: int) -> dict:
        if not (table := module.table(tableBaseAddress, tableIndex)): return dict()

        tableName = table.name().replace("::", "_")

        fields = dict()
        fieldCount = table.fieldCount()
        for fieldIndex in range(fieldCount):
            try: fields.update(cls.fieldDump(table, fieldIndex))
            except Exception: break

        return {tableName: fields}

    @classmethod
    def fieldDump(cls, table: RecvTable, fieldIndex: int) -> dict:
        if (field := table.field(fieldIndex)) is None: return dict()

        fieldName = field.name()
        fieldValue = field.value()

        return {fieldName: fieldValue}