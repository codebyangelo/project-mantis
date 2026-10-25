"""
Mantis radare2 Forensics & Section Reconstruction Subsystem.
Provides fail-closed execution, boundary clamping, and dumped PE/ELF repair.
"""

from .parser import EntropyProfile, R2BinaryInfo, R2Opcode, R2Section
from .reconstructor import reconstruct_dumped_pe
from .wrapper import R2Wrapper

__all__ = [
    "EntropyProfile",
    "R2BinaryInfo",
    "R2Opcode",
    "R2Section",
    "R2Wrapper",
    "reconstruct_dumped_pe",
]
