import os
import sys
import unittest

# Ensure src/ is on sys.path for test runners executing outside an installed wheel
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from mantis.sieve_deterministic import AllocationType, MalfindAllocation


class TestSieve(unittest.TestCase):
    def test_allocation_types(self):
        self.assertEqual(AllocationType.CFG.value, "cfg")
        self.assertEqual(AllocationType.JIT_PADDING.value, "jit_padding")

    def test_malfind_allocation(self):
        alloc = MalfindAllocation(
            start_vpn="0x1000",
            end_vpn="0x2000",
            protection="PAGE_EXECUTE_READWRITE",
            tag="VadS",
            disasm="movabs rax, addr",
            hexdump="48 b8",
            process_name="evil.exe",
            pid=1337,
        )
        self.assertEqual(alloc.process_name, "evil.exe")
        self.assertEqual(alloc.pid, 1337)


if __name__ == "__main__":
    unittest.main()
