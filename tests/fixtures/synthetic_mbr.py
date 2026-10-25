"""
Synthetic MBR/GPT Partition Fixture for Project Mantis.
Implements binary generation and boundary verification for raw disk blocks.
"""

import struct
from typing import Dict, List, Optional, Tuple

MBR_SECTOR_SIZE = 512
MBR_BOOTSTRAP_SIZE = 446
MBR_PARTITION_ENTRY_SIZE = 16
MBR_NUM_PARTITIONS = 4
MBR_MAGIC_SIGNATURE = b"\x55\xAA"

# Standard partition types
PARTITION_TYPE_NTFS = 0x07
PARTITION_TYPE_FAT32 = 0x0B
PARTITION_TYPE_LINUX = 0x83
PARTITION_TYPE_GPT_PROTECTIVE = 0xEE


from mantis.exceptions import (
    MantisBoundaryError,
    MantisTruncatedBlockError,
    MantisInvalidBootSignatureError,
    MantisOutOfBoundsPartitionError,
)


def encode_partition_record(
    bootable: bool = False,
    partition_type: int = PARTITION_TYPE_NTFS,
    start_lba: int = 2048,
    sector_count: int = 204800,
) -> bytes:
    """Encodes a single 16-byte MBR partition record."""
    status = 0x80 if bootable else 0x00
    # CHS addresses (stubbed to 0 for LBA-addressed partitions)
    chs_start = b"\x00\x00\x00"
    chs_end = b"\x00\x00\x00"
    return struct.pack(
        "<B3sB3sII",
        status,
        chs_start,
        partition_type,
        chs_end,
        start_lba,
        sector_count,
    )


def build_mbr(
    partitions: Optional[List[bytes]] = None,
    signature: bytes = MBR_MAGIC_SIGNATURE,
    bootstrap_filler: bytes = b"\x90",
) -> bytes:
    """Constructs a 512-byte MBR binary block."""
    bootstrap = (bootstrap_filler * (MBR_BOOTSTRAP_SIZE // len(bootstrap_filler) + 1))[
        :MBR_BOOTSTRAP_SIZE
    ]

    parts = list(partitions or [])
    while len(parts) < MBR_NUM_PARTITIONS:
        parts.append(b"\x00" * MBR_PARTITION_ENTRY_SIZE)

    partition_table = b"".join(parts[:MBR_NUM_PARTITIONS])
    return bootstrap + partition_table + signature


def generate_valid_ntfs_mbr(
    start_lba: int = 2048,
    sector_count: int = 204800,
) -> bytes:
    """Generates a valid MBR sector with one active NTFS partition."""
    ntfs_part = encode_partition_record(
        bootable=True,
        partition_type=PARTITION_TYPE_NTFS,
        start_lba=start_lba,
        sector_count=sector_count,
    )
    return build_mbr(partitions=[ntfs_part])


def generate_gpt_protective_mbr() -> bytes:
    """Generates a standard UEFI GPT protective MBR."""
    gpt_part = encode_partition_record(
        bootable=False,
        partition_type=PARTITION_TYPE_GPT_PROTECTIVE,
        start_lba=1,
        sector_count=0xFFFFFFFF,
    )
    return build_mbr(partitions=[gpt_part])


def generate_truncated_mbr(length: int = 511) -> bytes:
    """Generates an adversarial truncated MBR block (<512 bytes)."""
    full_mbr = generate_valid_ntfs_mbr()
    return full_mbr[:length]


def generate_corrupt_signature_mbr(signature: bytes = b"\x00\x00") -> bytes:
    """Generates an adversarial MBR with invalid magic boot signature."""
    return build_mbr(signature=signature)


def parse_and_validate_mbr(
    data: bytes,
    total_image_bytes: Optional[int] = None,
) -> List[Dict[str, int]]:
    """
    Forensic boundary parser implementing fail-closed invariants.
    Validates sector size, magic trailer, and extent bounds against image capacity.
    """
    if len(data) < MBR_SECTOR_SIZE:
        raise MantisTruncatedBlockError(
            f"Candidate MBR block is truncated ({len(data)} bytes < {MBR_SECTOR_SIZE} bytes)."
        )

    signature = data[510:512]
    if signature != MBR_MAGIC_SIGNATURE:
        raise MantisInvalidBootSignatureError(
            f"Invalid MBR signature: expected 0x55AA, got 0x{signature.hex()}."
        )

    partitions = []
    table_offset = MBR_BOOTSTRAP_SIZE

    for idx in range(MBR_NUM_PARTITIONS):
        entry_start = table_offset + (idx * MBR_PARTITION_ENTRY_SIZE)
        entry = data[entry_start : entry_start + MBR_PARTITION_ENTRY_SIZE]
        status, _, ptype, _, lba_start, sectors = struct.unpack("<B3sB3sII", entry)

        if ptype == 0x00 or sectors == 0:
            continue

        start_byte = lba_start * MBR_SECTOR_SIZE
        length_bytes = sectors * MBR_SECTOR_SIZE
        end_byte = start_byte + length_bytes

        if total_image_bytes is not None and end_byte > total_image_bytes:
            raise MantisOutOfBoundsPartitionError(
                f"Partition {idx} extent ({end_byte} bytes) exceeds total image size ({total_image_bytes} bytes)."
            )

        partitions.append({
            "index": idx,
            "bootable": (status == 0x80),
            "type": ptype,
            "start_lba": lba_start,
            "sectors": sectors,
            "start_byte": start_byte,
            "length_bytes": length_bytes,
        })

    return partitions
