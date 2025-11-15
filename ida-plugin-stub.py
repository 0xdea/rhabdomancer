import idaapi

class RhabdomancerStub(idaapi.plugin_t):
    flags = 0
    comment = "Stub for rhabdomancer (based on idalib's Rust bindings)"
    help = "This plugin is a stub and does not provide any functionality."
    wanted_name = "rhabdomancer"
    wanted_hotkey = ""

    def init(self):
        print(
            "[WARN] rhabdomancer is a headless plugin based on idalib's Rust bindings and should be used via the "
            "`rhabdomancer` crate via crates.io or from source, not as a regular IDA plugin."
        )
        return idaapi.PLUGIN_SKIP

    def run(self, arg):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    if not hasattr(PLUGIN_ENTRY, "_inst"):
        PLUGIN_ENTRY._inst = RhabdomancerStub()
    return PLUGIN_ENTRY._inst
