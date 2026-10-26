# Documentation: `courtroom.py`

## Overview

The `courtroom.py` module implements **Courtroom Code-Mode** for Project Mantis. Inspired by the architectural strength of Camel (3rd place, SANS Find Evil), which produced executable code to enable verifiable forensic validation, this module transitions Mantis from emitting purely natural-language incident summaries to synthesizing **standalone, executable Python verification scripts**.

In legal and regulatory proceedings, an assertion such as *"The LLM determined this memory allocation looks like malware"* is inadmissible hearsay. Mantis resolves this by embedding self-contained Python scripts directly into Section 8 of the MITRE incident report. Any independent forensic examiner, opposing counsel, or magistrate can execute the script to reproduce the forensic finding byte-for-byte in under 50 milliseconds.

---

## Architectural Breakdown

```
orchestrator.py (generate_mitre_report)
       │
       ▼
CourtroomScriptGenerator.generate_code_mode_section(isolated_threats)
       │
       ├─► Compute SHA-256 hash of raw evidence image
       ├─► Extract byte offset and signature pattern (e.g. 0x48B8 trampoline)
       ├─► Synthesize standalone Python script with deterministic exit codes
       └─► Embed into Section 8: 'Courtroom Admissibility (Code-Mode Reproduction)'
```

---

## Component Details: `CourtroomScriptGenerator`

### 1. Methods

#### `generate_reproduction_script(...) -> str`
- **Signature**:
  ```python
  @staticmethod
  def generate_reproduction_script(
      evidence_file: str,
      offset: int,
      expected_hex: str,
      sample_size: int = 64,
      description: str = "Malicious Trampoline / Injection Stub",
  ) -> str
  ```
- **Generated Script Capabilities**:
  1. **Zero External Dependencies**: Operates exclusively using standard Python library modules (`hashlib`, `os`, `sys`).
  2. **Evidence Integrity Verification**: Computes the SHA-256 hash of the evidence image and compares it against the recorded forensic baseline.
  3. **Precision Seeking**: Seeks directly to `offset` and reads `sample_size` bytes.
  4. **Byte Matching**: Compares extracted bytes against `expected_hex`.
  5. **Deterministic Forensic Exit Codes**:
     - `0`: Success. Finding verified byte-exact.
     - `1`: Evidence file not found on disk.
     - `2`: Evidence file hash mismatch (evidence has been tampered with or corrupted).
     - `3`: Byte pattern mismatch at specified offset.

#### `generate_code_mode_section(isolated_threats: list[dict]) -> str`
- **Purpose**: Generates the complete Markdown content for Section 8 of the final incident report.
- **Header Format**: `## 8. Courtroom Admissibility (Code-Mode Reproduction)`.
- **Output**: Markdown blocks containing executable Python reproduction scripts for each confirmed malicious entity.

---

## Operational Verification Example

When an examiner executes an emitted verification script:

```bash
python3 verify_threat_pid1042.py
```

*Output (Success):*
```text
[+] Evidence Integrity Verified: /evidence/memdump.raw
    SHA-256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
[+] Offset Reached: 0x100000 (1048576)
[+] Extracted 64 bytes: 48b80010400000000000ffe0...
[+] Match Confirmed: Header matches expected pattern '48b8'
[+] Courtroom Admissible Proof Confirmed: PID 1042 Malicious Trampoline verified.
```
*Process Exit Code: `0`*
