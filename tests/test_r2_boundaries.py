"""
Unit tests for Radare2 Upstream Boundary Hardening (Phase 3).
Tests fail-closed sector validation, cache invalidation, clamped streaming,
radare2 execution safety, and dumped PE/ELF section reconstruction.
"""

import io
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from mantis.config import CACHE_DIR
from mantis.exceptions import (
    MANTIS_RC_BOUNDARY_VIOLATION,
    MANTIS_RC_FAILURE,
    MANTIS_RC_TIMEOUT,
    MantisBoundaryError,
    MantisOutOfBoundsPartitionError,
    MantisR2Error,
    MantisReconstructionError,
)
from mantis.extractor import (
    ClampedStreamReader,
    detect_partition_offset,
    invalidate_evidence_cache,
    validate_sector_bounds,
)
from mantis.r2.parser import (
    parse_binary_info,
    parse_disasm,
    parse_entropy,
    parse_sections,
)
from mantis.r2.reconstructor import reconstruct_dumped_pe
from mantis.r2.wrapper import R2Wrapper


class TestSectorBoundsValidation(unittest.TestCase):
    """Tests validate_sector_bounds enforcing radare2 PR #26606 cmd_seek model."""

    def test_valid_sector_offset_returns_offset(self):
        # 10 MB image, offset 2048 (byte offset 1,048,576)
        image_size = 10 * 1024 * 1024
        validated = validate_sector_bounds(offset=2048, image_size=image_size)
        self.assertEqual(validated, 2048)

    def test_none_sector_offset_fails_closed(self):
        with self.assertRaises(MantisBoundaryError) as ctx:
            validate_sector_bounds(offset=None, image_size=1000000)
        self.assertEqual(ctx.exception.code, MANTIS_RC_FAILURE)

    def test_sector_zero_reserved_fails_closed(self):
        # Sector 0 contains MBR/boot metadata, not target partition
        with self.assertRaises(MantisBoundaryError) as ctx:
            validate_sector_bounds(offset=0, image_size=1000000)
        self.assertEqual(ctx.exception.code, MANTIS_RC_BOUNDARY_VIOLATION)

    def test_negative_sector_offset_fails_closed(self):
        with self.assertRaises(MantisBoundaryError) as ctx:
            validate_sector_bounds(offset=-1, image_size=1000000)
        self.assertEqual(ctx.exception.code, MANTIS_RC_BOUNDARY_VIOLATION)

    def test_out_of_bounds_offset_fails_closed(self):
        # 1 MB image (2048 sectors). Sector 2048 is out of bounds.
        image_size = 1024 * 1024
        with self.assertRaises(MantisOutOfBoundsPartitionError) as ctx:
            validate_sector_bounds(offset=2048, image_size=image_size)
        self.assertEqual(ctx.exception.code, MANTIS_RC_BOUNDARY_VIOLATION)

    def test_out_of_bounds_large_offset_fails_closed(self):
        image_size = 512 * 100
        with self.assertRaises(MantisOutOfBoundsPartitionError):
            validate_sector_bounds(offset=9999, image_size=image_size)


class TestCacheInvalidation(unittest.TestCase):
    """Tests cache state purging before early returns."""

    def setUp(self):
        os.makedirs(CACHE_DIR, exist_ok=True)
        self.test_files = [
            os.path.join(CACHE_DIR, "test_cache_target.json"),
            os.path.join(CACHE_DIR, "bodyfile_test_image.txt"),
        ]
        for f in self.test_files:
            with open(f, "w") as fp:
                fp.write("{}")

    def tearDown(self):
        for f in self.test_files:
            if os.path.exists(f):
                os.remove(f)

    def test_invalidate_by_cache_name(self):
        invalidated = invalidate_evidence_cache(cache_name="test_cache_target")
        self.assertFalse(os.path.exists(self.test_files[0]))
        self.assertTrue(any("test_cache_target.json" in path for path in invalidated))

    def test_invalidate_by_image_path(self):
        invalidated = invalidate_evidence_cache(image_path="/evidence/test_image.raw")
        self.assertFalse(os.path.exists(self.test_files[1]))
        self.assertTrue(any("bodyfile_test_image.txt" in path for path in invalidated))


class TestClampedStreamReader(unittest.TestCase):
    """Tests memory-clamped stream reading (<1.3GB RAM runner invariant)."""

    def test_clamped_reading_within_extent_bounds(self):
        # 100 KB total buffer
        data = b"A" * (100 * 1024)
        stream = io.BytesIO(data)

        # Extent bounds: 10KB to 30KB (total 20KB extent)
        extent_start = 10 * 1024
        extent_end = 30 * 1024
        stream.seek(extent_start)

        reader = ClampedStreamReader(
            stream=stream,
            extent_start=extent_start,
            extent_end=extent_end,
            chunk_size=4096,
        )

        read_bytes = b"".join(list(reader))
        self.assertEqual(len(read_bytes), 20 * 1024)
        self.assertEqual(reader.current_offset, extent_end)

    def test_chunk_size_clamped_to_max_heap_limit(self):
        stream = io.BytesIO(b"X" * 100)
        # Attempting 10MB chunk must be clamped to 64KB max
        reader = ClampedStreamReader(stream=stream, chunk_size=10 * 1024 * 1024)
        self.assertEqual(reader.chunk_size, ClampedStreamReader.MAX_CHUNK_SIZE)

    def test_clamped_reader_empty_stream(self):
        stream = io.BytesIO(b"")
        reader = ClampedStreamReader(stream=stream)
        chunks = list(reader)
        self.assertEqual(chunks, [])


class TestR2WrapperExecution(unittest.TestCase):
    """Tests radare2 fail-closed execution wrapper."""

    def test_missing_binary_fails_closed(self):
        wrapper = R2Wrapper(r2_bin="/nonexistent/bin/radare2")
        with self.assertRaises(MantisR2Error):
            wrapper.disassemble("/tmp/nonexistent", 0, 5)

    def test_failed_command_raises_mantis_r2_error(self):
        wrapper = R2Wrapper(r2_bin="python3")
        # Run python with non-zero exit code
        with self.assertRaises(MantisR2Error) as ctx:
            wrapper.run_command(["python3", "-c", "import sys; sys.exit(42)"])
        self.assertEqual(ctx.exception.code, 42)

    def test_command_timeout_raises_timeout_error(self):
        wrapper = R2Wrapper(r2_bin="python3", timeout=1)
        with self.assertRaises(MantisR2Error) as ctx:
            wrapper.run_command(["python3", "-c", "import time; time.sleep(5)"], timeout=1)
        self.assertEqual(ctx.exception.code, MANTIS_RC_TIMEOUT)

    def test_get_env_includes_ld_library_path(self):
        wrapper = R2Wrapper(extra_lib_paths=["/tmp/custom_lib"])
        with patch("os.path.exists", return_value=True):
            env = wrapper.get_env()
            self.assertIn("LD_LIBRARY_PATH", env)
            self.assertIn("/tmp/custom_lib", env["LD_LIBRARY_PATH"])


class TestR2Parsers(unittest.TestCase):
    """Tests JSON parsing from radare2/rabin2/rahash2."""

    def test_parse_binary_info_valid(self):
        sample = '{"core": {"arch": "x86", "bits": 64, "os": "windows", "bclass": "PE32+", "compiler": "msvc"}}'
        info = parse_binary_info(sample)
        self.assertEqual(info.arch, "x86")
        self.assertEqual(info.bits, 64)
        self.assertEqual(info.os, "windows")
        self.assertEqual(info.bin_type, "PE32+")

    def test_parse_binary_info_invalid_json_fails_closed(self):
        with self.assertRaises(MantisR2Error):
            parse_binary_info("INVALID_JSON")

    def test_parse_sections_valid(self):
        sample = '{"sections": [{"name": ".text", "size": 4096, "vsize": 4096, "vaddr": 4198400, "flags": "r-x"}]}'
        sections = parse_sections(sample)
        self.assertEqual(len(sections), 1)
        self.assertEqual(sections[0].name, ".text")
        self.assertEqual(sections[0].flags, "r-x")

    def test_parse_disasm_valid(self):
        sample = '[{"offset": 4198400, "size": 3, "opcode": "xor eax, eax", "bytes": "31c0"}]'
        opcodes = parse_disasm(sample)
        self.assertEqual(len(opcodes), 1)
        self.assertEqual(opcodes[0].opcode, "xor eax, eax")

    def test_parse_entropy_valid(self):
        sample = '{"entropy": 7.42}'
        profile = parse_entropy(sample)
        self.assertAlmostEqual(profile.overall_entropy, 7.42)


class TestDumpedBinaryReconstructor(unittest.TestCase):
    """Tests reconstruct_dumped_pe section repair."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_missing_input_file_raises_reconstruction_error(self):
        src = os.path.join(self.temp_dir, "missing.bin")
        dst = os.path.join(self.temp_dir, "repaired.exe")
        with self.assertRaises(MantisReconstructionError):
            reconstruct_dumped_pe(src, dst)

    def test_empty_input_file_raises_reconstruction_error(self):
        src = os.path.join(self.temp_dir, "empty.bin")
        dst = os.path.join(self.temp_dir, "repaired.exe")
        with open(src, "wb"):
            pass  # 0 bytes
        with self.assertRaises(MantisReconstructionError):
            reconstruct_dumped_pe(src, dst)

    def test_successful_pe_reconstruction_mocked(self):
        src = os.path.join(self.temp_dir, "malfind_dump.bin")
        dst = os.path.join(self.temp_dir, "repaired.exe")
        with open(src, "wb") as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 512)

        mock_wrapper = MagicMock()
        mock_wrapper.rabin2_bin = "/usr/bin/rabin2"
        mock_wrapper.run_command.return_value = MagicMock(returncode=0)

        success = reconstruct_dumped_pe(src, dst, wrapper=mock_wrapper)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(dst))
        mock_wrapper.run_command.assert_called_once()
        args = mock_wrapper.run_command.call_args[0][0]
        self.assertIn("-O", args)
        self.assertIn("r", args)
        self.assertIn("p", args)

    def test_corrupt_output_header_raises_reconstruction_error(self):
        src = os.path.join(self.temp_dir, "bad_dump.bin")
        dst = os.path.join(self.temp_dir, "corrupt.exe")
        with open(src, "wb") as f:
            f.write(b"\x00\x00\x00\x00" + b"\x00" * 512)

        mock_wrapper = MagicMock()
        mock_wrapper.rabin2_bin = "/usr/bin/rabin2"
        mock_wrapper.run_command.return_value = MagicMock(returncode=0)

        with self.assertRaises(MantisReconstructionError):
            reconstruct_dumped_pe(src, dst, wrapper=mock_wrapper)


class TestDetectPartitionOffsetFailClosed(unittest.TestCase):
    """Tests detect_partition_offset fail-closed behavior on non-existent or invalid images."""

    def test_detect_partition_offset_missing_file_fails_closed(self):
        result = detect_partition_offset("/tmp/nonexistent_image_12345.raw")
        self.assertIsNone(result)

    def test_detect_partition_offset_invalid_mmls_fails_closed(self):
        with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as f:
            f.write(b"\x00" * 1024)
            temp_path = f.name

        try:
            with patch("subprocess.check_output", side_effect=Exception("mmls parse failure")):
                result = detect_partition_offset(temp_path)
                self.assertIsNone(result)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()
