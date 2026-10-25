# Sieve Deterministic Module (`sieve_deterministic.py`)

## 1. Overview and Architectural Context

The `sieve_deterministic.py` module is a core deterministic classification layer for Project Mantis v0.5.2. In the broader system architecture, this layer sits strategically between the **SMPT** (which extracts memory allocations and anomalies) and the **Orchestrator** (which manages task allocation, including handing off to LLMs). 

### Purpose
The primary purpose of this module is to perform fast, rule-based, deterministic triage of memory allocations flagged by tools like `malfind` (commonly used in memory forensics to find hidden or injected code). By applying known regular expressions and heuristics, it can immediately classify certain behaviors as `MALICIOUS` or `BENIGN` with 100% confidence. This dramatically reduces the workload on downstream, expensive, and slower LLM-based analysis components, reserving them only for allocations that truly require deeper, context-aware reasoning.

---

## 2. Core Data Structures (Bottom-Up Analysis)

The module defines several critical data structures that form the vocabulary used to describe memory allocations and analysis results.

### 2.1 `AllocationType` Enum
Defines the strictly enumerated categories into which a memory allocation's disassembled code can be classified:
* **`CFG` (Control Flow Guard):** Recognizes benign arithmetic checks (e.g., `movabs rax, addr; sub rcx, rax`) that do not involve immediate redirection jumps.
* **`JIT_PADDING` (Just-In-Time Compilation Padding):** Represents benign JIT compiler behaviors, typically consisting of short relative jumps, `add [rax], al` padding, or `int3` sleds.
* **`TRAMPOLINE`:** Represents malicious arbitrary redirection (e.g., loading an absolute address into a register and jumping to it: `movabs rax, addr; jmp rax`).
* **`DEFENDER_EMULATION`:** A highly specific, benign pattern associated exclusively with Windows Defender (`MsMpEng.exe`), consisting of a jump to `rdx` followed by `int3`.
* **`UNKNOWN`:** Fallback classification for memory allocations that do not match any known deterministic pattern.

### 2.2 `MalfindAllocation` Dataclass
Represents a single anomalous memory region extracted from a process. It holds both the metadata and the actual content of the allocation:
* **Virtual Page Numbers:** `start_vpn` and `end_vpn`.
* **Memory Metadata:** `protection` (e.g., RWX) and `tag` (pool tag or memory type).
* **Content:** `disasm` (the disassembled instructions) and `hexdump` (the raw bytes).
* **Process Context:** `process_name` and `pid`.

### 2.3 `ProcessVerdict` Dataclass
The ultimate output of the module. It encapsulates the deterministic conclusion for an entire process.
* **Target Identification:** `pid` and `process_name`.
* **Conclusion:** 
  * `verdict`: Can be `"MALICIOUS"`, `"BENIGN"`, or `"NEEDS_REVIEW"`.
  * `confidence`: Float value (usually `1.0` for deterministic matches, `0.5` for unknowns).
  * `deterministic`: Boolean flag (always `True` for this module).
  * `reasoning`: A human-readable explanation of why the verdict was reached, often referencing specific incident response playbooks.
* **Evidence:** `critical_allocations` (malicious hits) and `benign_allocations` (safe hits).
* **Orchestration Flag:** `requires_llm_audit` (Boolean indicating if the Orchestrator needs to forward this to an LLM).

---

## 3. Pattern Matching Engine (`MalfindClassifier`)

The `MalfindClassifier` class is a stateless utility class containing the regex definitions and the business logic for classification.

### 3.1 Regular Expression Signatures
The module utilizes compiled regular expressions to parse the `disasm` string. These are engineered to match specific assembly paradigms ignoring case:
1. **`TRAMPOLINE_RE`**: `movabs\s+rax,\s*(0x[0-9a-f]+)\s*;\s*(?:0x[0-9a-f]+:\s*)?jmp\s+rax`
   * Looks for an absolute address loaded into `rax` followed by a `jmp rax`. This is a classic indicator of Process Injection/API Hooking trampolines.
2. **`JIT_RE`**: `jmp\s+(0x[0-9a-f]+)\s*;\s*(?:0x[0-9a-f]+:\s*)?add\s+byte\s+ptr\s*\[\s*rax\s*\]\s*,\s*al`
   * Looks for a short jump followed immediately by memory addition padding (`add byte ptr [rax], al`), a signature of .NET or V8 JIT engines.
3. **`CFG_RE`**: `movabs\s+rax,\s*(0x[0-9a-f]+)\s*;\s*(?:0x[0-9a-f]+:\s*)?sub\s+rcx\s*,\s*rax`
   * Looks for an absolute address loaded into `rax` followed by a subtraction against `rcx`. This is standard Control Flow Guard validation logic.
4. **`DEFENDER_RE`**: `jmp\s+r[0-9a-z]{1,2}\b`
   * A loose regex looking for an indirect jump via a register, specifically used alongside `int3` to identify Defender.

### 3.2 Allocation-Level Triage (`classify_allocation`)
This static method takes a single `MalfindAllocation` and returns an `AllocationType`.
* **Preprocessing:** It normalizes the disassembly by replacing newlines with semicolons (`;`) to allow regexes to easily match multi-instruction sequences.
* **Defender Special Case:** If the process is `msmpeng.exe`, it checks for `DEFENDER_RE` and the literal string `int3`. If both are present, it returns `DEFENDER_EMULATION`.
* **Regex Cascade:** It tests `TRAMPOLINE_RE`, then `JIT_RE`, then `CFG_RE`. Priority is crucial here; `TRAMPOLINE` is the most specific and dangerous, so it is checked first.
* **Heuristics Fallback:** If regexes fail, it counts occurrences of `int3` and `add byte ptr [rax], al`. If `int3 > 3` or `add > 2`, it probabilistically classifies the region as `JIT_PADDING`.
* **Default:** Returns `UNKNOWN`.

### 3.3 Process-Level Triage (`evaluate_process`)
This class method aggregates a list of `MalfindAllocation` objects for a single process and generates a holistic `ProcessVerdict`.

#### The Verdict Flow
1. **Empty State:** If no allocations are provided, it immediately returns `BENIGN` with `1.0` confidence.
2. **Classification Mapping:** Every allocation is classified using `classify_allocation`.
3. **Rule 1: The Malicious Short-Circuit**
   * If *any* allocation is classified as `TRAMPOLINE`, the entire process is burned.
   * **Verdict:** `MALICIOUS` (Confidence `1.0`).
   * **Playbook:** Maps to `PROC_INJ_001` (Process Injection).
   * **LLM Audit:** `False`.
4. **Rule 2: The Defender Exception**
   * If the process is `MsMpEng.exe` and contains `DEFENDER_EMULATION` patterns.
   * **Verdict:** `BENIGN` (Confidence `1.0`).
   * **Playbook:** Maps to `FP_004` (Legitimate behavior / False Positive).
   * **LLM Audit:** `False`.
5. **Rule 3: Known Benign Patterns**
   * If the allocations consist entirely of `JIT_PADDING` and/or `CFG` (and lack trampolines or defender logic).
   * **Verdict:** `BENIGN` (Confidence `1.0`).
   * **LLM Audit:** `False`.
6. **Rule 4: The Unknowns (The LLM Handoff)**
   * If the allocations do not trigger the malicious rule, but contain `UNKNOWN` patterns.
   * **Verdict:** `NEEDS_REVIEW` (Confidence `0.5`).
   * **LLM Audit:** `True`. This is the crucial trigger that tells the Orchestrator to pass the context to an LLM for advanced heuristic or semantic review.

---

## 4. Summary
`sieve_deterministic.py` is a highly efficient, regex-and-heuristic-driven screening mechanism. By operating strictly on known architectural artifacts (like JIT compilation traits, CFG implementations, and standard trampoline hooking techniques), it acts as a "Sieve" that filters out absolute known-good (benign JIT/CFG) and absolute known-bad (trampolines), routing only the ambiguous gray-area allocations to the more resource-intensive LLM evaluators.
