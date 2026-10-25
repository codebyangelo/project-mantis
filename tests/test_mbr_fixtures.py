"""
Unit test suite proving fail-closed partition boundary parsing against synthetic MBR fixtures.
"""

import os
import sys
import unittest

# Ensure src/ is on sys.path
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from tests.fixtures.synthetic_mbr import (
    PARTITION_TYPE_GPT_PROTECTIVE,
    PARTITION_TYPE_NTFS,
    MantisInvalidBootSignatureError,
    MantisOutOfBoundsPartitionError,
    MantisTruncatedBlockError,
    generate_corrupt_signature_mbr,
    generate_gpt_protective_mbr,
    generate_truncated_mbr,
    generate_valid_ntfs_mbr,
    parse_and_validate_mbr,
)


class TestSyntheticMBRBoundaries(unittest.TestCase):
    def test_valid_ntfs_mbr_parsing(self):
        mbr_data = generate_valid_ntfs_mbr(start_lba=2048, sector_count=204800)
        total_size = (2048 + 204800 + 1000) * 512

        partitions = parse_and_validate_mbr(mbr_data, total_image_bytes=total_size)
        self.assertEqual(len(partitions), 1)

        part = partitions[0]
        self.assertEqual(part["type"], PARTITION_TYPE_NTFS)
        self.assertTrue(part["bootable"])
        self.assertEqual(part["start_lba"], 2048)
        self.assertEqual(part["start_byte"], 2048 * 512)
        self.assertEqual(part["length_bytes"], 204800 * 512)

    def test_gpt_protective_mbr_parsing(self):
        mbr_data = generate_gpt_protective_mbr()
        partitions = parse_and_validate_mbr(mbr_data, total_image_bytes=None)
        self.assertEqual(len(partitions), 1)
        self.assertEqual(partitions[0]["type"], PARTITION_TYPE_GPT_PROTECTIVE)
        self.assertEqual(partitions[0]["start_lba"], 1)

    def test_truncated_mbr_fails_closed(self):
        """Proves that a 511-byte truncated sector raises an explicit MantisTruncatedBlockError."""
        truncated_data = generate_truncated_mbr(length=511)
        with self.assertRaises(MantisTruncatedBlockError) as ctx:
            parse_and_validate_mbr(truncated_data)
        self.assertIn("truncated", str(ctx.exception).lower())

    def test_corrupt_signature_fails_closed(self):
        """Proves that missing 0x55AA signature raises MantisInvalidBootSignatureError."""
        corrupt_data = generate_corrupt_signature_mbr(signature=b"\x00\x00")
        with self.assertRaises(MantisInvalidBootSignatureError) as ctx:
            parse_and_validate_mbr(corrupt_data)
        self.assertIn("0x0000", str(ctx.exception))

    def test_out_of_bounds_partition_fails_closed(self):
        """Proves that a partition extent extending beyond image size raises MantisOutOfBoundsPartitionError."""
        # Partition spans up to 105 MB, but total image is constrained to 50 MB
        mbr_data = generate_valid_ntfs_mbr(start_lba=2048, sector_count=204800)
        constrained_image_bytes = 50 * 1024 * 1024

        with self.assertRaises(MantisOutOfBoundsPartitionError) as ctx:
            parse_and_validate_mbr(mbr_data, total_image_bytes=constrained_image_bytes)
        self.assertIn("exceeds total image size", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
