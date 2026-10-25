"""
Synthetic Malfind Allocation Fixtures for Project Mantis Verification.
Generates realistic telemetry allocations for proving the deterministic sieve.
"""

import os
import sys

# Ensure src/ is on sys.path
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from mantis.sieve_deterministic import MalfindAllocation


def make_trampoline_allocation(
    pid: int = 1337,
    process_name: str = "svchost_injected.exe",
    target_addr: str = "0x7ffd12345678",
    start_vpn: str = "0x1b40000",
    end_vpn: str = "0x1b50000",
) -> MalfindAllocation:
    """Creates an allocation exhibiting a malicious shellcode trampoline pattern."""
    disasm = (
        f"0x1b40000:\tmovabs rax, {target_addr}\n"
        f"0x1b4000a:\tjmp rax\n"
        f"0x1b4000c:\tint3\n"
    )
    hexdump = "48 b8 78 56 34 12 fd 7f 00 00 ff e0 cc cc cc cc"
    return MalfindAllocation(
        start_vpn=start_vpn,
        end_vpn=end_vpn,
        protection="PAGE_EXECUTE_READWRITE",
        tag="VadS",
        disasm=disasm,
        hexdump=hexdump,
        process_name=process_name,
        pid=pid,
    )


def make_jit_padding_allocation(
    pid: int = 2048,
    process_name: str = "node.exe",
    start_vpn: str = "0x2000000",
    end_vpn: str = "0x2010000",
) -> MalfindAllocation:
    """Creates a benign JIT engine allocation with nearby jump and NOP/add padding."""
    disasm = (
        "0x2000000:\tjmp 0x2000010\n"
        "0x2000005:\tadd byte ptr [rax], al\n"
        "0x2000007:\tadd byte ptr [rax], al\n"
        "0x2000009:\tadd byte ptr [rax], al\n"
    )
    hexdump = "eb 0e 00 00 00 00 00 00 00 00 00 00 00 00 90 90"
    return MalfindAllocation(
        start_vpn=start_vpn,
        end_vpn=end_vpn,
        protection="PAGE_EXECUTE_READWRITE",
        tag="Vad",
        disasm=disasm,
        hexdump=hexdump,
        process_name=process_name,
        pid=pid,
    )


def make_cfg_allocation(
    pid: int = 3100,
    process_name: str = "msedge.exe",
    check_addr: str = "0x7fff89ab0000",
    start_vpn: str = "0x3000000",
    end_vpn: str = "0x3020000",
) -> MalfindAllocation:
    """Creates a benign Control Flow Guard check allocation (arithmetic test without jump)."""
    disasm = (
        f"0x3000000:\tmovabs rax, {check_addr}\n"
        f"0x300000a:\tsub rcx, rax\n"
        f"0x300000d:\ttest rcx, rcx\n"
    )
    hexdump = "48 b8 00 00 ab 89 ff 7f 00 00 48 29 c1 48 85 c9"
    return MalfindAllocation(
        start_vpn=start_vpn,
        end_vpn=end_vpn,
        protection="PAGE_EXECUTE_READWRITE",
        tag="VadS",
        disasm=disasm,
        hexdump=hexdump,
        process_name=process_name,
        pid=pid,
    )


def make_defender_emulation_allocation(
    pid: int = 400,
    process_name: str = "MsMpEng.exe",
    start_vpn: str = "0x4000000",
    end_vpn: str = "0x4010000",
) -> MalfindAllocation:
    """Creates a benign Windows Defender emulation engine allocation."""
    disasm = (
        "0x4000000:\tjmp rdx\n"
        "0x4000003:\tint3\n"
        "0x4000004:\tint3\n"
    )
    hexdump = "ff e2 cc cc 90 90 90 90"
    return MalfindAllocation(
        start_vpn=start_vpn,
        end_vpn=end_vpn,
        protection="PAGE_EXECUTE_READWRITE",
        tag="Vad",
        disasm=disasm,
        hexdump=hexdump,
        process_name=process_name,
        pid=pid,
    )


def make_unknown_shellcode_allocation(
    pid: int = 5500,
    process_name: str = "powershell.exe",
    start_vpn: str = "0x5000000",
    end_vpn: str = "0x5010000",
) -> MalfindAllocation:
    """Creates an unrecognized polymorphic shellcode allocation requiring LLM review."""
    disasm = (
        "0x5000000:\tcld\n"
        "0x5000001:\tand rsp, 0xfffffffffffffff0\n"
        "0x5000005:\tcall 0x500001a\n"
        "0x500000a:\tpop rdi\n"
    )
    hexdump = "fc 48 83 e4 f0 e8 10 00 00 00 5f 48 89 e5"
    return MalfindAllocation(
        start_vpn=start_vpn,
        end_vpn=end_vpn,
        protection="PAGE_EXECUTE_READWRITE",
        tag="VadS",
        disasm=disasm,
        hexdump=hexdump,
        process_name=process_name,
        pid=pid,
    )
