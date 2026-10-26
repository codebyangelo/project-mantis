# Mantis Extractor (`extractor.py`)

## Overview

The `extractor.py` module is a core orchestration and extraction component of the Mantis forensic framework. It is responsible for triaging, classifying, and extracting critical digital artifacts from various forensic image types—namely memory dumps, physical disk images, and network captures (PCAPs). By tightly integrating with external digital forensics and incident response (DFIR) tools such as Volatility 3 and The Sleuth Kit (TSK), the extractor acts as the bridge between raw forensic evidence and the normalized cache system utilized by downstream analysis modules (like `sieve.py` and `orchestrator.py`).

---

## Architecture and Hardened Boundary Principles

The architecture of `extractor.py` is engineered with low-level systems safety invariants inspired by upstream Radare2 security fixes:

1. **Memory-Conscious Stream Clamping (radare2 Issue #12924 Precedent)**:
   Forensic images frequently contain corrupt or weaponized headers designed to trigger out-of-memory (OOM) conditions. Mantis introduces `ClampedStreamReader`, enforcing a strict heap buffer ceiling of 64KB (`MAX_CHUNK_SIZE = 65536`). Reads are mathematically clamped to:
   $$\text{chunk\_size} = \min(\text{requested\_buffer}, \text{extent\_end} - \text{current\_offset}, 65536)$$
   This guarantees that memory consumption remains under the 1.3GB unprivileged runner ceiling during high-throughput carving.
2. **Fail-Closed Sector Bounds Checking (radare2 PR #26606 Precedent)**:
   Before passing partition offsets to disk readers or SleuthKit commands, `validate_sector_bounds()` pre-parses and validates sector boundaries against the physical image file size. If an offset exceeds physical boundaries or overflows, it raises `MantisOutOfBoundsPartitionError` fail-closed rather than allowing out-of-bounds seeks.
3. **Pre-Return Cache Invalidation (Cache Poisoning Prevention)**:
   If an extraction routine encounters truncated data blocks, read failures, or non-zero subprocess exit codes, `invalidate_evidence_cache()` immediately deletes the destination cache file. This guarantees that corrupted or partial data never persists in the cache to mislead downstream triage agents.
4. **Cache-Oriented Output**: Every extracted artifact is normalized into structured JSON and stored in a designated cache directory (`CACHE_DIR`), maintaining both unique (per-evidence) and aggregate tables.
5. **Deep Forensic Capabilities**: Provides targeted streaming and carving for high-value targets including EVTX logs, Windows Prefetch files, LNK shortcuts, and memory-resident strings.

---

## Top-Down Execution Flow

The `main()` function serves as the extraction entrypoint:
1. **Argument Parsing**: Accepts command-line flags (`--deep`, `--memory`, `--disk`, `--registry`, `--evtx`, `--prefetch`, `--lnk`, `--pcap`). If no flags are provided, it executes all extraction modules.
2. **Cache Initialization**: Clears legacy aggregated cache files (e.g., `pstree.json`, `registry_map.json`) to prevent cross-contamination.
3. **Image Classification**: Iterates over files in `EVIDENCE_DIR` and categorizes them into memory, disk, or network images via `classify_image()`.
4. **Context Generation**: Creates `context.json` mapping the investigation to discovered evidence files.
5. **Sequential Processing Pipeline**:
   * **Memory Processing**: Ingests memory dumps through Volatility 3 plugins (`pstree`, `cmdline`, `malfind`, `netscan`, `hivelist`).
   * **Disk Processing**: Parses partition offsets via `detect_partition_offset()`, executes `validate_sector_bounds()`, generates filesystem bodyfiles via `fls`, and maps registry hives via `prcarve_registry_map()`.
   * **Network Processing**: Extracts ASCII strings and matches HTTP/DNS/credential indicators from PCAPs.

---

## Bottom-Up Analysis: Core Boundary Functions

### 1. `validate_sector_bounds(disk_image_path, sector_offset, sector_size=512) -> int`
* **Purpose**: Enforces fail-closed sector boundary validation prior to executing SleuthKit commands.
* **Mechanism**: Obtains physical disk size using `os.path.getsize()`. Verifies that `sector_offset * sector_size <= file_size`.
* **Exceptions**: Raises `MantisOutOfBoundsPartitionError` if sector offset exceeds file size; raises `FileNotFoundError` if disk image is missing.

### 2. `invalidate_evidence_cache(cache_file_path: str) -> None`
* **Purpose**: Removes stale or partial cache targets to prevent cache poisoning.
* **Mechanism**: Verifies existence of `cache_file_path`, logs cache invalidation via `ExecutionLogger`, and deletes the file cleanly.

### 3. `ClampedStreamReader` Class
* **Attributes**: `MAX_CHUNK_SIZE = 65536` (64KB heap ceiling).
* **Methods**:
  - `clamp_chunk_size(requested_size: int, remaining_bytes: int | None = None) -> int`: Computes bounded buffer size.
  - `read_clamped_stream(stream, total_bytes: int | None = None)`: Generator yielding clamped byte blocks.

### 4. Disk Extraction & Inode Streaming
* **`detect_partition_offset(disk_image_path)`**: Uses `mmls` to identify partition layouts. Validates sector boundaries with `validate_sector_bounds()` and returns the validated start sector offset.
* **`carve_and_stream_strings(disk_image_path, inode, output_name, keywords, chunk_size=65536)`**: Streams file contents by inode using `icat -r`. Employs `ClampedStreamReader` to process output in 64KB chunks while performing on-the-fly ASCII and UTF-16LE keyword matching.

---

## Dependencies & Invariants
- **External Binaries**: `vol` (Volatility 3), `mmls`, `fls`, `icat` (The Sleuth Kit).
- **Domain Exceptions**: Imports `MantisOutOfBoundsPartitionError`, `MantisTruncatedBlockError`, and `MantisBoundaryError` from `.exceptions`.
- **Heap Ceiling**: Strictly $<64\text{ KB}$ per chunk read.
