import CS2


cs2 = CS2.Pymem("cs2.exe")

# Signatures
signatures = CS2.SignatureDump.dump(cs2, CS2.SignatureDump.signaturesConfigOnline())
signatures = CS2.Utils.dict2Class(signatures)

# Schemas
schemas = CS2.SchemaDump.dump(cs2)
schemas = CS2.Utils.dict2Class({moduleName.replace(".", "_"): CS2.Utils.dict2Class({**{tableName: CS2.Utils.dict2Class({**table, **{"__dict__": schemas.get(moduleName).get(tableName)}}) for tableName, table in module.items()}, **{"__dict__": schemas.get(moduleName)}}) for moduleName, module in schemas.items()})








