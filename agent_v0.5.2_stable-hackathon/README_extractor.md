# Mantis Extractor (`extractor.py`)

## Overview

The `extractor.py` module is a core orchestration and extraction component of the Mantis forensic framework. It is responsible for triaging, classifying, and extracting critical digital artifacts from various forensic image types—namely memory dumps, physical disk images, and network captures (PCAPs). By tightly integrating with external digital forensics and incident response (DFIR) tools such as Volatility and The Sleuth Kit (TSK), the extractor acts as the bridge between raw forensic evidence and the normalized cache system utilized by downstream analysis modules (like `sieve.py`).

## Architecture and Design Principles

The architecture of `extractor.py` is highly modular and designed with the following core principles in mind:

1.  **Memory-Conscious Processing**: The tool is engineered to process massive forensic images without overwhelming system RAM. Instead of loading binary files into memory, it uses chunk-based reading (1MB chunks) and streams outputs directly from forensic utilities (like `icat`) to parse strings dynamically.
2.  **Cache-Oriented Output**: Every extracted artifact is immediately normalized into JSON and stored in a designated cache directory (`CACHE_DIR`). This includes both unique cache files (tied to a specific evidence file) and aggregate cache files (combining findings across all evidence files).
3.  **Resilience and Fallbacks**: The module incorporates robust error handling, featuring fallback mechanisms (e.g., falling back to native byte inspection if manifest data is missing, or defaulting to offset 0 if `mmls` fails) and subprocess timeouts.
4.  **Deep Forensic Capabilities**: Beyond standard plugin execution, the extractor provides a "Deep Mode" that carves and streams specific high-value targets like EVTX logs, Prefetch files, LNK shortcuts, and memory-resident strings.

## Top-Down Execution Flow

The `main()` function serves as the entry point and orchestrates the extraction process in a top-down manner:

1.  **Argument Parsing**: Accepts command-line flags to dictate the scope of the extraction (`--deep`, `--memory`, `--disk`, `--registry`, `--evtx`, `--prefetch`, `--lnk`, `--pcap`). If no specific flags are provided, it defaults to a full extraction (running all modules).
2.  **Cache Initialization**: Clears out legacy aggregated cache files (e.g., `pstree.json`, `registry_map.json`) to prevent cross-contamination between runs.
3.  **Image Classification**: Iterates over files in the `EVIDENCE_DIR` and categorizes them into memory, disk, or network images using the `classify_image()` function.
4.  **Context Generation**: Creates a central `context.json` file in the cache directory, mapping the Investigation ID ("PM-AUTOGEN") to the discovered evidence files. This establishes the global context for downstream tools.
5.  **Sequential Processing Pipeline**:
    *   **Memory Processing**: For each classified memory image, executes Volatility plugins (`pstree`, `cmdline`, `malfind`, `netscan`, `hivelist`).
    *   **Disk Processing**: For each disk image, it generates a filesystem bodyfile. If registry parsing is requested, it builds a registry map. If deep extraction flags are present, it initiates specific targeted string streaming for EVTX, Prefetch, and LNK files.
    *   **Network Processing**: For PCAPs, it reads and extracts strings related to HTTP/DNS/authentication.

## Bottom-Up Analysis: Core Components and Functions

### 1. Evidence Classification
*   **`classify_image(file_path)`**: Determines the image type via a three-tiered approach:
    1.  **Manifest Check**: First consults `manifest.json` in the evidence directory for a pre-defined label.
    2.  **Extension Check**: Checks standard extensions (`.mem`, `.vmem` for memory; `.e01`, `.vmdk` for disk; `.pcap` for network).
    3.  **Native Byte Inspection**: For ambiguous extensions like `.dd` or `.img`, it seeks to byte `510` to check for an MBR signature (`\x55\xaa`) or byte `512` for a GPT signature (`EFI PART`). If neither is found, it defaults to memory.

### 2. Memory Extraction (Volatility Integration)
*   **`run_plugin(image_path, plugin, args=[])`**: A wrapper around the `vol` (Volatility) command. It enforces JSON output and includes timeout handling to prevent indefinite hangs during complex memory parsing.
*   **`parse_and_cache(raw_json, cache_name, image_path)`**: Processes the JSON output from `run_plugin`. It writes two files:
    *   A unique file: e.g., `pstree_image1.json`
    *   An aggregate file: e.g., `pstree.json` (appending/merging data across multiple memory images).
*   **Targeted Extractors**: Functions like `extract_pstree`, `extract_cmdline`, `extract_malfind`, `extract_netscan`, and `extract_hivelist` serve as convenient wrappers around `run_plugin` and `parse_and_cache` for specific Volatility plugins.

### 3. Disk Extraction (The Sleuth Kit Integration)
*   **`detect_partition_offset(disk_image_path)`**: Uses `mmls` to parse the partition table. It intelligently looks for the largest NTFS or "Basic data partition" and extracts its starting sector offset, passing this to downstream tools.
*   **`generate_bodyfile(disk_image_path, output_path)`**: Executes `fls` (utilizing the offset from `detect_partition_offset`) to recursively generate a bodyfile (a timeline/metadata map) of the entire file system.
*   **`prcarve_registry_map(disk_image_path)`**: Parses the generated bodyfile to locate critical registry hives (`SYSTEM`, `SOFTWARE`, `NTUSER.DAT`). It maps these files to their respective inode numbers, allowing targeted extraction without mounting the image.

### 4. Deep Target Streaming (Ingenuity Engine)
*   **`carve_and_stream_strings(disk_image_path, inode, output_name, keywords)`**: The most sophisticated function in the module. It calls `icat` to extract a specific file by its inode directly from the raw disk image. Instead of loading the output into memory, it uses a `subprocess.PIPE` to read the stdout in 1MB chunks. It simultaneously carves ASCII and basic UTF-16LE strings and performs keyword matching on the fly.
*   **Deep Extractors**:
    *   `extract_evtx_stream`: Uses the bodyfile to find `.evtx` files (specifically Security and System) and streams them through `carve_and_stream_strings` looking for keywords like "mimikatz", "powershell", and "logon".
    *   `extract_prefetch_stream`: Locates `.pf` files and streams them looking for execution artifacts (e.g., ".exe", "appdata").
    *   `extract_lnk_stream`: Locates `.lnk` files in recent folders to map out volume and file access patterns.

### 5. Network Extraction
*   **`extract_pcap_stream(pcap_path)`**: Similar to the disk string carver, this function reads a raw `.pcap` file natively in Python using 1MB chunks. It extracts ASCII strings and matches them against network-centric keywords (e.g., "http://", "user-agent:", "password").

## Artifact Caching Strategy
The system uses `CACHE_DIR` heavily to persist extracted data. This decouples the extraction phase from the analysis phase. The unique caching mechanism ensures that multi-evidence investigations do not overwrite each other's data, while the aggregate caching ensures backward compatibility with tools expecting unified datasets (like `sieve.py`).

## Dependencies
- **System Binaries**: `vol` (Volatility 3), `mmls`, `fls`, `icat` (The Sleuth Kit).
- **Python Modules**: `os`, `subprocess`, `json`, `re`, `time`, `argparse`.
- **Internal Modules**: `config.py` (for directory constants), `logger.py` (for standardizing output logs).
