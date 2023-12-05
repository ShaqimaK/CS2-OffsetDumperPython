from pymem import Pymem, process
from pymem.ressources.structure import MODULEINFO

from typing import Union
from inspect import signature as inspectSignature

from requests import get


from CS2.utils import Operation, pattern2Byte, infoPrinter
info = infoPrinter(__name__)





class SignatureDump:
    def __init__(self, cs2: Pymem): self.cs2 = cs2


    @classmethod
    def signature(cls, cs2: Pymem, module: Union[str, MODULEINFO], pattern: str, operations: Union[list, tuple], name: str = "None") -> Union[int, hex]:
        info("【Signature】【%s】" % name)
        module = process.module_from_name(cs2.process_handle, module) if isinstance(module, str) else module

        address = cs2.pattern_scan_module(pattern2Byte(pattern), module)
        info("———— PatternScan: %s (%s) -> %s (%i)" % (module.name, pattern, hex(address).upper().replace("X", "x"), address))

        operations = list() if operations is None else operations
        for operation in operations:
            address = getattr(Operation, operation.get("type"))(
                cs2, address,
                #**{key: value for key, value in operation.items() if key in [str(parameter) for parameter in inspectSignature(getattr(Operation, operation.get("type"))).parameters]}
                **{key: value for key, value in operation.items() if not key == "type"}
            )
            info("———— Operation (%i/%i): %s -> %s (%i)" % (operations.index(operation) + 1, len(operations), operation.get("type"), hex(address).upper().replace("X", "x"), address))

        address -= module.lpBaseOfDll * (address // module.lpBaseOfDll)

        info("———— FinalAddress -> %s (%i)" % (hex(address).upper().replace("X", "x"), address))
        return address


    @classmethod
    def dump(cls, cs2: Pymem, signaturesConfig: dict) -> dict:
        signaturesDict = dict()
        #signaturesConfig = get("https://raw.githubusercontent.com/a2x/cs2-dumper/main/config.json").json().get("signatures")
        for signature in signaturesConfig:
            signaturesDict.update({
                signature.get("name"):
                    cls.signature(
                        cs2,
                        signature.get("module"),
                        signature.get("pattern"),
                        signature.get("operations"),
                        name=signature.get("name")
                    )})
        return signaturesDict

    @classmethod
    def signaturesConfigOnline(cls) -> dict: return get("https://raw.githubusercontent.com/a2x/cs2-dumper/main/config.json").json().get("signatures")
