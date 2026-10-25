"""
Mantis radare2 Parser.
Transforms and validates JSON telemetry from radare2/rabin2/rahash2 into typed models.
"""

import json
from dataclasses import dataclass, field
from typing import Any

from ..exceptions import MantisR2Error


@dataclass
class R2BinaryInfo:
    """Represents core binary metadata parsed from rabin2 -j -I."""
    arch: str = "unknown"
    bits: int = 0
    os: str = "unknown"
    bin_type: str = "unknown"
    compiler: str = "unknown"
    endian: str = "little"
    stripped: bool = False
    static: bool = False
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class R2Section:
    """Represents executable section info parsed from rabin2 -j -S."""
    name: str = ""
    size: int = 0
    vsize: int = 0
    vaddr: int = 0
    paddr: int = 0
    flags: str = ""


@dataclass
class R2Opcode:
    """Represents a disassembled instruction opcode from radare2."""
    offset: int = 0
    size: int = 0
    opcode: str = ""
    disasm: str = ""
    bytes_hex: str = ""


@dataclass
class EntropyProfile:
    """Represents file or block entropy profile from rahash2."""
    overall_entropy: float = 0.0
    block_size: int = 0
    blocks: list[float] = field(default_factory=list)


def parse_binary_info(raw_json: str) -> R2BinaryInfo:
    """
    Parses output of rabin2 -j -I into R2BinaryInfo.
    Fails closed if the json is corrupt.
    """
    try:
        data = json.loads(raw_json)
        # rabin2 often nests info inside {"core": {...}, "bin": {...}}
        info_block = data.get("core", data.get("bin", data))
        if isinstance(info_block, list) and len(info_block) > 0:
            info_block = info_block[0]
        elif not isinstance(info_block, dict):
            info_block = {}

        return R2BinaryInfo(
            arch=str(info_block.get("arch", "unknown")),
            bits=int(info_block.get("bits", 0) or 0),
            os=str(info_block.get("os", "unknown")),
            bin_type=str(info_block.get("bclass", info_block.get("class", "unknown"))),
            compiler=str(info_block.get("compiler", "unknown")),
            endian=str(info_block.get("endian", "little")),
            stripped=bool(info_block.get("stripped", False)),
            static=bool(info_block.get("static", False)),
            raw=data if isinstance(data, dict) else {},
        )
    except Exception as e:
        raise MantisR2Error(f"Failed to parse rabin2 binary info: {e}") from e


def parse_sections(raw_json: str) -> list[R2Section]:
    """
    Parses output of rabin2 -j -S into a list of R2Section objects.
    """
    try:
        data = json.loads(raw_json)
        sections_list = data.get("sections", data) if isinstance(data, dict) else data
        if not isinstance(sections_list, list):
            return []

        results = []
        for s in sections_list:
            if not isinstance(s, dict):
                continue
            results.append(
                R2Section(
                    name=str(s.get("name", "")),
                    size=int(s.get("size", 0) or 0),
                    vsize=int(s.get("vsize", 0) or 0),
                    vaddr=int(s.get("vaddr", 0) or 0),
                    paddr=int(s.get("paddr", 0) or 0),
                    flags=str(s.get("flags", s.get("perm", ""))),
                )
            )
        return results
    except Exception as e:
        raise MantisR2Error(f"Failed to parse rabin2 sections: {e}") from e


def parse_disasm(raw_json: str) -> list[R2Opcode]:
    """
    Parses output of radare2 -qc pdj into a list of R2Opcode objects.
    """
    try:
        data = json.loads(raw_json)
        if not isinstance(data, list):
            return []

        results = []
        for item in data:
            if not isinstance(item, dict):
                continue
            results.append(
                R2Opcode(
                    offset=int(item.get("offset", 0) or 0),
                    size=int(item.get("size", 0) or 0),
                    opcode=str(item.get("opcode", "")),
                    disasm=str(item.get("disasm", item.get("opcode", ""))),
                    bytes_hex=str(item.get("bytes", "")),
                )
            )
        return results
    except Exception as e:
        raise MantisR2Error(f"Failed to parse radare2 disassembly: {e}") from e


def parse_entropy(raw_json: str) -> EntropyProfile:
    """
    Parses output of rahash2 entropy calculation.
    """
    try:
        data = json.loads(raw_json)
        entropy_val = 0.0
        if isinstance(data, dict):
            entropy_val = float(data.get("entropy", 0.0) or 0.0)
        return EntropyProfile(overall_entropy=entropy_val)
    except Exception as e:
        raise MantisR2Error(f"Failed to parse rahash2 entropy: {e}") from e
