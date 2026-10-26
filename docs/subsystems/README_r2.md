# Documentation: `r2/` Subsystem

## Overview

The `r2/` subsystem integrates the **Radare2 forensic reverse-engineering engine** into Project Mantis. It provides low-level binary dissection, disassembly, Shannon entropy profiling, and binary section re-alignment. Designed to operate safely in heterogeneous environments (including Android Termux and standard Linux distributions), it features **dynamic linker isolation** to prevent runtime library conflicts and enforces strict timeouts to prevent analysis hangs on corrupted binaries.

---

## Architectural Breakdown

```
src/mantis/r2/
├── __init__.py         # Re-exports R2Wrapper, parser models, and reconstructor
├── wrapper.py          # Process supervisor, linker isolation, tool resolution
├── parser.py           # Typed JSON telemetry parsers (disasm, entropy, sections)
└── reconstructor.py    # Memory-to-disk PE/ELF section repair (radare2 Issue #15449)
```

---

## Component Details

### 1. `R2Wrapper` (`wrapper.py`)
Supervises CLI execution of `radare2`, `rabin2`, and `rahash2` with fail-closed bounds:

#### Dynamic Linker Isolation (`_prepare_isolated_r2_lib_dir`)
* **The Problem:** In Android Termux or hybrid container environments, `/data/data/com.termux/files/usr/lib` contains foreign shared libraries compiled against Bionic libc. Adding this full path to `LD_LIBRARY_PATH` poisons the glibc dynamic loader for standard system binaries (such as `python3`), triggering immediate `Segmentation fault (core dumped) [139]`.
* **The Solution:** `_prepare_isolated_r2_lib_dir()` creates `~/.cache/mantis/r2_libs` and symlinks **only** `libr_*.so` files. It leaves all other foreign libraries isolated, ensuring radare2 tools find their dependencies without polluting the host Python environment.

#### Core Methods:
* `get_binary_info(file_path: str) -> R2BinaryInfo`: Invokes `rabin2 -j -I` to extract architecture, compiler, bits, and binary format.
* `get_sections(file_path: str) -> list[R2Section]`: Invokes `rabin2 -j -S` to extract section names, virtual memory addresses, sizes, and permissions.
* `disassemble(file_path: str, offset: int = 0, count: int = 10) -> list[R2Opcode]`: Invokes `r2 -qc "s <offset>; pdj <count>"` to disassemble instructions into typed opcode structures.
* `calculate_entropy(file_path: str, block_size: int = 1024) -> EntropyProfile`: Invokes `rahash2 -j -a entropy` to compute overall and block-level Shannon entropy.

### 2. Typed Data Models (`parser.py`)
* `R2BinaryInfo`: Dataclass containing `arch`, `bits`, `os`, `bin_type`, `compiler`, `endian`, `stripped`, `static`.
* `R2Section`: Dataclass containing `name`, `size`, `vsize`, `vaddr`, `paddr`, `flags`.
* `R2Opcode`: Dataclass containing `offset`, `size`, `opcode`, `disasm`, `bytes_hex`.
* `EntropyProfile`: Dataclass containing `overall_entropy`, `block_size`, and block-level entropy scores.

### 3. Binary Section Reconstructor (`reconstructor.py`)
* **Function**: `reconstruct_dumped_pe(dump_path: Path, output_path: Path) -> bool`
* **Upstream Invariant (radare2 Issue #15449)**: Memory dumps extracted via Volatility `malfind` contain PE/ELF binaries mapped to virtual memory rather than raw disk offsets. Headers and sections are misaligned, causing static analysis tools (`file`, `pefile`, YARA) to fail.
* **Mechanism**: Invokes `rabin2 -O r -O p` to resize virtual sections, synchronize headers, and patch section permissions. Verifies that the reconstructed binary starts with a valid magic header (`MZ` or `\x7fELF`).
