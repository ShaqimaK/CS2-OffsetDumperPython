from pymem import Pymem, process
from pymem.ressources.structure import MODULEINFO

from typing import Union
from inspect import signature as inspectSignature

from requests import get


from CS2.utils import Operation, debugPrint, pattern2Byte





class Signatures:
    def __init__(self, cs2: Pymem): self.cs2 = cs2


    @classmethod
    def signature(cls, cs2: Pymem, module: Union[str, MODULEINFO], pattern: str, operations: Union[list, tuple], name: str = "None") -> Union[int, hex]:
        debugPrint("【Signature】【%s】" % name)
        operations = list() if operations is None else operations
        module = process.module_from_name(cs2.process_handle, module) if isinstance(module, str) else module

        address = cs2.pattern_scan_module(pattern2Byte(pattern), module)
        debugPrint("———— PatternScan: %s (%s) -> %s (%i)" % (module.name, pattern, hex(address).upper().replace("X", "x"), address))

        for operation in operations:
            address = getattr(Operation, operation["type"])(
                cs2, address,
                **{key: value for key, value in operation.items() if key in [str(parameter) for parameter in inspectSignature(getattr(Operation, operation["type"])).parameters]})
            debugPrint("———— Operation: %s -> %s (%i)" % (operation["type"], hex(address).upper().replace("X", "x"), address))

        #debugPrint("———— DllBaseRemainder: %i" % (address // module.lpBaseOfDll))
        for _ in range(address // module.lpBaseOfDll):
            if address > module.lpBaseOfDll: address -= module.lpBaseOfDll

        debugPrint("———— FinalAddress -> %s (%i)" % (hex(address).upper().replace("X", "x"), address))
        return address


    @classmethod
    def dump(cls, cs2: Pymem, signaturesConfig: dict) -> dict:
        signaturesDict = dict()
        #signaturesConfig = get("https://raw.githubusercontent.com/a2x/cs2-dumper/main/config.json").json().get("signatures")
        for signature in signaturesConfig:
            signaturesDict.update({
                signature.get("name"):
                    cls.signature(cs2,
                                  signature.get("module"),
                                  signature.get("pattern"),
                                  signature.get("operations"),
                                  name=signature.get("name")
                                  )})
        return signaturesDict

    @classmethod
    def signaturesConfigOnline(cls) -> dict: return get("https://raw.githubusercontent.com/a2x/cs2-dumper/main/config.json").json().get("signatures")




#signatures(Pymem("cs2.exe")).signaturesDump()
