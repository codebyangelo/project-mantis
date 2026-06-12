Gemini

### 1. The Roast (Executive Summary)

This codebase is a prime example of "demo-ware" masquerading as an elite DFIR tool. You have duct-taped a probabilistic Large Language Model to high-privilege system binaries using shell pipes, creating an architecture that is as stable and predictable as Eskom load-shedding during a Vryburg winter. You are treating strings and raw memory as trusted inputs and relying on hope-based regex parsing, assuming adversarial evidence will politely conform to your expectations.

Architecturally, attempting to force a generative model to act as a "deterministic state machine" for complex loop iteration is an exercise in futility. The state is smeared across the LLM's context window rather than strictly managed in Python. Furthermore, your error handling is virtually non-existent—swallowing tracebacks with bare `except Exception:` blocks guarantees that when this agent fails in the field, it will fail silently, hallucinate a successful extraction, and potentially corrupt the chain of custody.

### 2. Critical Vulnerabilities (P0 & P1)

* **P0: Arbitrary Command Injection via Evidence Filenames:**
Your entire `mcp_server.py` and `extractor.py` rely on executing shell pipelines using `shell=True` and string interpolation (f-strings).
*Example from `mcp_server.py`:*
`f"strings -a '{target_image}' | grep -iE '{regex_pattern}' ... "`
If an attacker names a memory dump `evidence'; rm -rf /; echo '.raw`, your automated agent executes it with the privileges of the forensic investigator. In a DFIR context, interacting with hostile artifacts using unchecked shell execution is a fatal operational security failure.
* **P1: Path Traversal in Cache Resolution:**
In `mcp_server.py`, the cache filenames are dynamically built using PID strings. If the LLM hallucinates or extracts a PID like `../../etc/passwd`, your `os.path.join(CACHE_DIR, f"pid.{pid_str}.dmp")` can traverse out of the safe directory and overwrite or read arbitrary files.
* **P1: Infinite API Burns on Bad JSON:**
In `orchestrator.py`, if the LLM enters a failure state where it cannot generate valid JSON, the `except json.JSONDecodeError:` block sends a prompt to force realignment and `continue`s the loop immediately. With no maximum retry limit, a model collapse will drain your API credits in minutes.

### 3. Performance & Reliability Flaws

* **Blocking I/O disguised as Concurrency:**
The `run_with_timer` function is a hack. You spin up a thread to run a synchronous `subprocess.run`, entirely so you can print a timer to the console. You have no `timeout` set on the subprocess. If `vol` or `icat` hangs on a corrupted E01 image (which happens constantly in real-world DFIR), your agent locks up permanently.
* **Brittle Output Parsing:**
Relying on `grep` and `head -n 30` to filter forensic artifacts is incredibly fragile. You are offloading forensic logic to OS binaries rather than utilizing native Python, which eliminates your ability to perform granular error checking or handle edge-case encodings (like UTF-16 strings in memory).

### 4. Actionable Refactoring Plan

We must immediately eradicate `shell=True` and handle the data pipelines entirely within Python, enforcing strict timeouts.

**BEFORE (The Vulnerable Code in `mcp_server.py`):**

```python
def extract_and_carve_hive(inode: str, disk_image_path: str) -> str:
    try:
        cmd = (
            f"icat -i ewf {disk_image_path} {inode} | "
            f"strings -el | grep -Fi 'C:\\' | grep -i '\\.dll' | "
            f"grep -ivE 'system32|syswow64|winsxs|program files|microsoft\\.net' | sort -u"
        )
        output = run_with_timer(cmd, task_name).strip()
        # ... 

```

**AFTER (Production-Grade Native Pipeline):**

```python
import subprocess
import os

def extract_and_carve_hive_secure(inode: str, disk_image_path: str) -> str:
    """Securely carves hives using native Popen chaining and Python filtering."""
    
    # Strict Type/Sanity Validation
    if not inode.replace('-', '').isdigit():
        return "[!] FATAL: Invalid inode format."
    if not os.path.isfile(disk_image_path):
        return "[!] FATAL: Disk image not found."

    icat_cmd = ["icat", "-i", "ewf", disk_image_path, inode]
    strings_cmd = ["strings", "-el"]
    
    try:
        # Native pipe chaining without shell=True
        icat_proc = subprocess.Popen(icat_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        strings_proc = subprocess.Popen(strings_cmd, stdin=icat_proc.stdout, stdout=subprocess.PIPE, text=True)
        
        # Allow icat to receive SIGPIPE if strings exits early
        icat_proc.stdout.close() 
        
        # Enforce strict timeout
        output, err = strings_proc.communicate(timeout=120)
        
        if strings_proc.returncode != 0:
            return f"[!] Strings pipeline failed: {err.strip()}"

        # Native Python filtering (replaces brittle grep)
        exclusions = ['system32', 'syswow64', 'winsxs', 'program files', 'microsoft.net']
        results = set()
        
        for line in output.splitlines():
            line_lower = line.lower()
            if 'c:\\' in line_lower and '.dll' in line_lower:
                if not any(excl in line_lower for excl in exclusions):
                    results.add(line.strip())

        if not results:
            return "[*] HIVE CARVE CLEAN."
            
        return "[!] ANOMALY DETECTED IN HIVE:\n" + "\n".join(sorted(results))

    except subprocess.TimeoutExpired:
        icat_proc.kill()
        strings_proc.kill()
        return "[!] ERROR: Forensic carve timed out after 120s."
    except Exception as e:
        return f"[!] FATAL EXECUTION ERROR: {str(e)}"

```

### 5. Prompt Engineering Critique

**The Flaw:** `[CRITICAL OVERRIDE] You are the Universal Forensic Engine (v0.1.4). You are a deterministic state machine.`

LLMs are structurally incapable of being deterministic state machines. By instructing the model to iterate over a list of PIDs using "Steps A through E", you are asking it to maintain an invisible stack trace in its memory across multiple API calls. As the context window fills with JSON responses, its attention mechanism will decay, and it will skip PIDs, hallucinate steps, or get stuck in a loop.

**The Fix:**
Shift the iteration logic out of the LLM and into Python. The LLM should only evaluate *one PID at a time*.

1. Python runs `malfind` and gets the list of anomalous PIDs.
2. Python initiates a `for pid in anomalous_pids:` loop.
3. Inside the loop, Python calls the LLM, handing it a single discrete task: *"Here is the telemetry for PID 4864 (pstree, cmdline, registry, netscan). Is this benign or malicious?"*
4. The LLM acts as an analysis engine, not an orchestrator. It returns its finding, and Python handles the state transition to the next PID.

# PRODUCT REQUIREMENTS DOCUMENT (PRD)

**Project:** Find Evil – Architecture & Security Overhaul (v0.1.4 → v0.1.5)
**Author:** Principal Security Architect
**Status:** LOCKED_IN | **Priority:** P0 (Critical Blockers Identified)
**Location Context:** Vryburg, ZA (Engine must account for high-latency, intermittent connectivity, and sudden offline states)

---

## 1. Executive Summary

The v0.1.4 proof-of-concept demonstrated utility but is fundamentally non-viable for production DFIR environments. It currently operates as an insecure, non-deterministic shell-script wrapper masquerading as an AI agent. We are stripping this down to the studs.

Version 0.1.5 will eradicate all command injection vectors, enforce strict Python-native state management, and relegate the LLM from "System Orchestrator" to "Stateless Analysis Engine." The new architecture must be hardened, asynchronous, and resilient enough to survive offline environments and API throttling without silently corrupting evidence.

---

## 2. Problem Statement (The Tech Debt)

The current implementation introduces unacceptable risks into the chain of custody:

1. **P0 Security Flaws:** The use of `shell=True` and f-string interpolation across `extractor.py` and `mcp_server.py` allows adversarial artifacts to achieve local privilege escalation and command injection on the forensic workstation.
2. **Architectural Hallucination:** Forcing a probabilistic LLM to act as a deterministic state loop over multiple PIDs guarantees context collapse, skipped evidence, and infinite API token burns.
3. **Fragile Data Pipelines:** Relying on OS-level `grep`, `head`, and `strings` via piped subprocesses is brittle, drops edge-case encodings (UTF-16), and leads to thread-locking deadlocks when Volatility hangs.
4. **Path Traversal Risks:** Dynamic cache paths built from unsanitized LLM output allow arbitrary file reads/writes outside the designated `EVIDENCE_DIR`.

---

## 3. Product Vision & Goals

**Vision:** An uncompromising, autonomous DFIR agent that parses memory and disk artifacts locally, only querying the LLM for high-order heuristic evaluation of strictly sanitized data.

**Core Goals:**

* **Zero-Trust I/O:** Treat all evidence files, filenames, and LLM outputs as highly hostile.
* **Deterministic Control Flow:** Python controls the iteration; the AI acts strictly as an evaluator.
* **Native Processing:** Replace all bash utilities with native Python regex, struct parsing, and byte-level analysis.
* **Asynchronous Resilience:** Implement `asyncio` for non-blocking Volatility executions with hard timeouts.

---

## 4. Architectural Overhaul

### 4.1. Decoupling State Management

The LLM will no longer receive the "Steps A through E" instructions.

* **The Router (Python):** `orchestrator.py` will autonomously query the `malfind` cache natively, extract anomalous PIDs, and iterate through them using a standard `for` loop.
* **The Evaluator (LLM):** During each loop iteration, Python bundles the context for a *single* PID (pstree, cmdline, netscan, carved strings) and ships it to the LLM.
* **Strict Output Schema:** The LLM must output a strictly defined JSON evaluation for that specific PID, which Python parses to decide whether to pivot to the next PID or flag for human review.

### 4.2. Concurrency & Asynchronous I/O

Move away from the blocking `run_with_timer` thread hack.

* Implement Python's `asyncio.subprocess` to manage `vol` and `icat`.
* Enforce strict `asyncio.wait_for` timeouts (e.g., 120 seconds maximum per memory dump). If a process hangs, send `SIGKILL`, log the failure to the ledger, and proceed.

### 4.3. Native Data Pipelines

* Eradicate `grep` and `strings` bash commands.
* Implement an optimized Python generator to read raw memory/hives in chunks, utilizing `re.finditer` with compiled regex patterns for ASCII and UTF-16 strings to prevent memory exhaustion and eliminate shell execution.

---

## 5. Security & Engineering Requirements

### 5.1. Subprocess Hardening

* **Requirement:** `shell=True` is strictly forbidden across the entire codebase.
* **Implementation:** All external commands must be invoked using `subprocess.Popen` or `asyncio.create_subprocess_exec` passing arguments as a strictly separated list (e.g., `["vol", "-f", img, "windows.pstree"]`).

### 5.2. Path Traversal Prevention

* **Requirement:** All dynamic file paths must be resolved and locked to a designated sandbox directory.
* **Implementation:** Implement a `resolve_safe_path(base_dir, user_input)` utility that uses `os.path.abspath` and verifies the resulting path starts with `base_dir` before any read/write operations occur.

### 5.3. API Circuit Breakers

* **Requirement:** The system must not burn API credits if the LLM enters a failure loop.
* **Implementation:** Implement a hard limit of 3 retry attempts for `JSONDecodeError`. If it fails 3 times sequentially, halt execution, dump state to `thoughts.txt`, and raise a `FatalLLMCollapse` exception.

### 5.4. Intermittent Connectivity Tolerance (SA Context)

* **Requirement:** The orchestrator must gracefully handle sudden network drops to the Google API (common during Stage 6+ loadshedding or local ISP routing issues).
* **Implementation:** Wrap all `genai.Client` calls in an asynchronous exponential backoff queue. If the connection drops, pause execution, queue the telemetry payload, and retry indefinitely at 60-second intervals until connectivity is restored, preventing data loss.

---

## 6. Implementation Phases

### Phase 1: Security & Foundation (Weeks 1-2)

* Refactor `extractor.py` and `mcp_server.py` to use `subprocess.run(args_list)` exclusively.
* Implement the native Python memory carver to replace the `strings | grep` pipeline.
* Implement `resolve_safe_path()` for all cache and evidence handling.

### Phase 2: Engine Rewrite (Weeks 3-4)

* Rewrite `orchestrator.py` to use `asyncio`.
* Strip the "deterministic state machine" logic from the LLM prompt in `agent.py`.
* Hardcode the PID iteration loop in Python.

### Phase 3: Telemetry, API, & UX (Week 5)

* Implement the API circuit breakers and exponential backoff for network resilience.
* Finalize the MITRE ATT&CK report generator to ensure cryptographic sealing functions correctly with the new asynchronous output.
* Deploy stress tests against highly corrupted memory images to validate timeout handling.


Copilot

## 1. The Roast (Executive Summary)

This codebase is a brittle prototype masquerading as a DFIR agent. The so‑called “deterministic state machine” is neither deterministic nor a state machine—it’s a JSON cache duct‑taped to LLM prompts. Any hallucination, malformed JSON, or decode error will collapse the orchestration instantly. The architecture is monolithic, with orchestration logic, subprocess execution, and extraction routines tangled together. Error handling is superficial at best, with silent exception swallowing and zero resilience against tool hangs (Volatility, sleuthkit). This is not production‑grade DFIR automation; it’s a fragile demo that would implode under adversarial or real‑world forensic workloads.

Security posture is indefensible. Subprocess calls are constructed with f‑strings and concatenated paths, opening the door to command injection and path traversal. External data from memory/disk images is piped directly into shell commands without sanitization. Unsafe deserialization and unchecked JSON parsing make this agent exploitable by anyone who can influence its inputs. Performance is equally bad: synchronous blocking calls for memory carving and disk extraction guarantee bottlenecks. There’s no concurrency, no watchdogs, no timeout enforcement. In short: this is a toy, not a tool. If deployed in the field, it would be a liability.

---

## 2. Critical Vulnerabilities (P0 & P1)

- **Command Injection**: `run_command` and `subprocess.run` use f‑strings with unsanitized user/system input. A crafted disk path or Volatility plugin name could execute arbitrary shell commands.  
- **Path Traversal**: No validation on file paths; attackers can escape working directories.  
- **Unsafe JSON Parsing**: Blind `json.loads()` on LLM output—hallucinations or malicious payloads crash or poison state.  
- **Silent Exception Swallowing**: `try/except` blocks that log nothing, leaving failures invisible.  
- **No Timeout Enforcement**: Volatility or sleuthkit hangs indefinitely, freezing the agent.  
- **LLM Hallucination Risk**: Routing decisions are based on vague prompts; adversarial input can misroute or corrupt state.

---

## 3. Performance & Reliability Flaws

- **Synchronous IO**: Memory carving and disk extraction block the entire agent.  
- **No Concurrency**: No multiprocessing or asyncio; multi‑GB images stall the orchestrator.  
- **Cache Fragility**: JSON cache is single‑point‑of‑failure; corruption bricks the agent.  
- **Race Conditions**: Shared state across orchestrator/extractor with no locks.  
- **Fallback Parsers**: Pure Python MBR/GPT parser crashes on malformed headers—no resilience.

---

## 4. Actionable Refactoring Plan

### Example: Subprocess Execution

**Before (bad code):**
```python
def run_command(cmd):
    result = subprocess.run(f"{cmd}", shell=True, capture_output=True)
    return result.stdout
```

**After (production-grade):**
```python
import subprocess
import shlex

def run_command(cmd_list, timeout=30):
    try:
        safe_cmd = [shlex.quote(arg) for arg in cmd_list]
        result = subprocess.run(
            safe_cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        raise RuntimeError("Command timed out")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Command failed: {e.stderr}")
```

### Example: JSON Parsing

**Before (bad code):**
```python
state = json.loads(llm_output)
```

**After (production-grade):**
```python
import json

def safe_json_parse(data):
    try:
        return json.loads(data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")
```

### Example: Async Extraction

**Before (bad code):**
```python
def extract_disk(image):
    run_command(["icat", image])
```

**After (production-grade):**
```python
import asyncio

async def extract_disk(image):
    proc = await asyncio.create_subprocess_exec(
        "icat", image,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"icat failed: {stderr.decode()}")
    return stdout
```

---

## 5. Prompt Engineering Critique

The system prompt in `agent.py` is brittle. It tries to enforce determinism with rigid JSON schemas, but the instructions are vague and underspecified. The LLM is asked to “route forensic tasks” without strong guardrails, so hallucinations or ambiguous outputs break orchestration.  

**Fixes:**
- Use **structured output** (e.g., JSON schema validation with retries).  
- Add **self‑consistency checks**: require the LLM to explain its reasoning before emitting JSON.  
- Implement **multi‑step verification**: parse, validate, and confirm outputs before execution.  
- Make prompts **explicit and bounded**: enumerate valid actions, forbid free‑form text, enforce strict schema compliance.

---

This codebase is a liability in its current form. If you want this agent to survive real DFIR workloads, you need to gut the orchestration, enforce strict validation, and rebuild subprocess handling with hardened wrappers. Would you like me to draft a **full architectural redesign** that replaces the JSON‑LLM “state machine” with a verifiable, event‑driven workflow?

Alright, here’s a **Production Requirements Document (PRD)** for the way forward on *Project Find Evil (v0.1.4)*. This is not a gentle roadmap—it’s a surgical teardown and rebuild plan. I’ll structure it as a formal PRD with explicit goals, requirements, risks, and deliverables.  

---

# Project Find Evil (v0.1.5) – PRD

## 1. Executive Summary
The current agent is a brittle prototype. It relies on unsafe subprocess execution, fragile JSON‑LLM orchestration, synchronous blocking IO, and nonexistent resilience. This PRD defines the requirements for transforming the agent into a **production‑grade, event‑driven DFIR automation system** with hardened security, concurrency, and verifiable orchestration.

---

## 2. Objectives
- Replace fragile JSON‑LLM “state machine” with a **verifiable event‑driven workflow**.  
- Harden subprocess execution against **command injection** and **path traversal**.  
- Introduce **async IO** and **multiprocessing** for memory/disk extraction.  
- Implement **structured error handling** with logging, retries, and watchdogs.  
- Modularize orchestration, extraction, and server components for maintainability.  
- Enforce **schema validation** and **self‑consistency checks** in LLM routing.  

---

## 3. Scope & Deliverables

### 3.1 Architecture & State Management
- **Deliverable:** Event‑driven orchestrator using `asyncio` + message bus (e.g., `asyncio.Queue`).  
- **Requirement:** Deterministic state transitions defined in code, not inferred from LLM free‑form output.  
- **Validation:** JSON schema enforcement with retries; fallback to safe defaults if LLM output invalid.  

### 3.2 Security & Validation
- **Deliverable:** Hardened subprocess wrapper.  
- **Requirement:**  
  - Use `shlex.quote` for all arguments.  
  - Enforce `shell=False`.  
  - Add timeout + watchdog enforcement.  
- **Validation:** Static analysis + fuzz testing with malicious inputs.  

### 3.3 Performance & Concurrency
- **Deliverable:** Async extraction pipeline.  
- **Requirement:**  
  - Disk/memory carving via `asyncio.create_subprocess_exec`.  
  - Multiprocessing for CPU‑bound parsing (MBR/GPT).  
  - Non‑blocking orchestration.  
- **Validation:** Benchmarks on multi‑GB images; watchdog ensures no indefinite hangs.  

### 3.4 Error Handling & Resilience
- **Deliverable:** Unified error handling framework.  
- **Requirement:**  
  - No silent exception swallowing.  
  - Structured logging (JSON logs).  
  - Retry policies for transient failures.  
  - Fallback parsers with graceful degradation.  
- **Validation:** Chaos testing with malformed images, corrupted headers, and tool hangs.  

### 3.5 Code Quality & Maintainability
- **Deliverable:** Modular separation.  
  - `orchestrator.py` → event routing + state machine.  
  - `extractor.py` → disk/memory extraction.  
  - `mcp_server.py` → communication layer.  
- **Requirement:** DRY enforcement, unit tests per module.  
- **Validation:** Static analysis + coverage >85%.  

### 3.6 Prompt Engineering
- **Deliverable:** Hardened LLM orchestration.  
- **Requirement:**  
  - Explicit action enumeration.  
  - JSON schema validation with retries.  
  - Self‑consistency checks (LLM explains reasoning before emitting JSON).  
  - Multi‑step verification pipeline.  
- **Validation:** Adversarial prompt testing.  

---

## 4. Risks & Mitigations
- **Risk:** LLM hallucinations corrupt orchestration.  
  - *Mitigation:* Schema validation + fallback defaults.  
- **Risk:** Subprocess hangs.  
  - *Mitigation:* Timeout + watchdog enforcement.  
- **Risk:** Malformed disk headers crash parser.  
  - *Mitigation:* Multiprocessing isolation + graceful fallback.  
- **Risk:** Cache corruption bricks agent.  
  - *Mitigation:* Redundant state persistence (SQLite or LMDB).  

---

## 5. Milestones
- **M1 (Week 1–2):** Harden subprocess wrapper + safe JSON parser.  
- **M2 (Week 3–4):** Implement async extraction + watchdogs.  
- **M3 (Week 5–6):** Modularize orchestrator/extractor/server.  
- **M4 (Week 7–8):** Harden LLM prompt engineering + schema validation.  
- **M5 (Week 9):** Chaos testing + adversarial validation.  
- **M6 (Week 10):** Production readiness review.  

---

## 6. Success Metrics
- **Security:** Zero exploitable command injection/path traversal vectors.  
- **Performance:** Handle 10GB+ images without blocking orchestrator.  
- **Resilience:** Survive malformed inputs without crashing.  
- **Reliability:** >95% task completion under chaos testing.  
- **Maintainability:** >85% test coverage, modular separation enforced.  

---

This PRD is the **battle plan**. It’s not incremental patching—it’s a gut‑and‑replace strategy. The JSON‑LLM “state machine” dies here; what rises is a verifiable, event‑driven DFIR agent.  


Deepseek

## 1. The Roast (Executive Summary)

Let’s be blunt: **this is a clever prototype, not a production-ready tool.** You’ve built an LLM‑driven script that *might* work in a perfectly clean lab with a patient operator, but it would explode in a real incident. The architecture is held together by wishful thinking—you’re relying on a generative model to faithfully execute a deterministic, nested loop without any external state tracking. That’s like using a toddler to follow a 20‑step IKEA manual while blindfolded. The LLM *will* hallucinate PIDs, skip steps, forget to iterate, and produce malformed JSON. Your “mandatory heuristic loop” is a suggestion, not a constraint.

Security is equally terrifying. You’re building shell commands with `f‑strings` and passing unsanitized data from JSON caches (which an attacker could poison) directly to `subprocess.run(shell=True)`. That’s a **command injection buffet**. Performance? Every tool call is synchronous, you’ve inserted an arbitrary `sleep(4)` as “API Governor pacing” (what does that even mean?), and you’re running `strings` on multi‑gigabyte memory images without any streaming or progress reporting. The code is tightly coupled, error handling consists of `except: pass`, and the only thing separating this from ransomware is luck. This would never pass a security review, nor survive a real engagement.

## 2. Critical Vulnerabilities (P0 & P1)

### P0 – Command Injection via Unsanitized External Data
**Location:** `mcp_server.py` – `extract_and_carve_hive`, `carve_memory_strings`, `run_with_timer`  
**Why it’s P0:** An attacker who can write to any cache file (or influence `inode`, `regex_pattern`, `disk_image_path`) can execute arbitrary commands on the forensic workstation.

```python
# extract_and_carve_hive – malicious inode example
cmd = f"icat -i ewf {disk_image_path} {inode} | strings ..."
# inode from registry_map.json – if attacker writes "123; rm -rf /" ...
```

**Fix:** Never use `shell=True`. Use `subprocess.run` with argument list, and validate/whitelist all inputs.

### P0 – Path Traversal in `query_json_cache`
**Location:** `mcp_server.py:query_json_cache`  
`cache_name` from LLM (indirectly user‑influenced) is concatenated into a file path.  
`../etc/passwd` would read arbitrary files.

```python
filepath = os.path.join(CACHE_DIR, f"{cache_name}.json")
```

**Fix:** Reject any `cache_name` containing `/`, `\`, `..`, or use `os.path.basename` after whitelisting.

### P1 – Unbounded Subprocess Hangs (No Timeouts)
**Location:** All `subprocess.run` calls, especially `run_with_timer` (which does **not** set a timeout).  
Volatility, `icat`, `strings` on corrupted images can hang forever, freezing the agent.

**Fix:** Add `timeout` parameter to every `subprocess.run` and handle `TimeoutExpired`.

### P1 – LLM Hallucination / State Loss
**Location:** `orchestrator.py` – no persistent state for PID iteration.  
The LLM may skip PIDs, process the same PID twice, or claim completion early.  
The prompt says “for every single PID … you MUST” but the agent has no way to enforce it.

**Fix:** Move state management to Python. Let the LLM only decide **next action** given the current state (e.g., current PID index, remaining PIDs list). Use a structured state machine.

### P1 – Unsafe Deserialization of JSON from Cache
**Location:** `mcp_server.py:query_json_cache` – `json.loads(raw_content)` on files that may be attacker‑controlled.  
Though not `pickle`, malformed JSON causes exceptions that are swallowed. Worse, if a future feature uses `yaml.load` or similar, it’s RCE.

**Fix:** Validate JSON schema before loading, and limit recursion depth/size.

## 3. Performance & Reliability Flaws

### Worst Bottlenecks
- **Synchronous memory carving** – `carve_memory_strings` runs `strings` on the entire memory image (or process dump). For a 16GB RAM image, this takes minutes to hours. Caching helps only for repeated identical queries.
- **`extractor.py --deep`** – runs `malfind`, `netscan` on the memory image **before** the agent even starts. If the analyst wants quick triage, they can’t skip it. The agent also cannot request on‑demand scanning.
- **Arbitrary `time.sleep(4)`** – `orchestrator.py` line ~130 adds 4 seconds **after every tool call**. This makes a 20‑step investigation take 80 seconds of pure delay, for no reason.
- **Volatility plugin execution** – each plugin reads the entire memory image again (unless Volatility 3 caches internally, but you don’t control that). `pstree`, `cmdline`, `netscan`, `malfind` each re‑parse the same image.

### Race Conditions / Reliability Issues
- **No locking on cache writes** – `orchestrator.py` and `extractor.py` both write to `CACHE_DIR` concurrently (e.g., `bodyfile.txt` generation while agent runs). Corruption likely.
- **`extract_and_carve_hive` fallback** – walks `EVIDENCE_DIR` recursively searching for `SYSTEM`/`SOFTWARE` files. On a mounted forensic image with millions of files, this will take forever and may match wrong files.
- **`run_with_timer`** – uses a busy‑sleep thread and `sys.stdout.write` without flushing properly. The timer thread is not a real timeout; the subprocess can still hang indefinitely.

## 4. Actionable Refactoring Plan

Below are critical fixes with **Before** (your code) and **After** (production‑grade) examples.

### 4.1 Command Injection – Replace `shell=True` with List Arguments

**Before (`extract_and_carve_hive`):**
```python
cmd = (
    f"icat -i ewf {disk_image_path} {inode} | "
    f"strings -el | grep -Fi 'C:\\' | grep -i '\\.dll' | ..."
)
output = run_with_timer(cmd, task_name)
```

**After (safe & modular):**
```python
def safe_icat_and_filter(disk_image_path: str, inode: str) -> str:
    # Validate inode format (e.g., digits-dash-digits)
    if not re.fullmatch(r"\d+-\d+-\d+", inode):
        raise ValueError(f"Invalid inode format: {inode}")
    
    # Use list form, no shell
    icat_proc = subprocess.run(
        ["icat", "-i", "ewf", disk_image_path, inode],
        capture_output=True, timeout=300, check=False
    )
    if icat_proc.returncode != 0:
        return ""  # or raise
    
    strings_proc = subprocess.run(
        ["strings", "-el"],
        input=icat_proc.stdout, capture_output=True, timeout=60
    )
    # Use Python regex filtering instead of grep (avoid shell)
    lines = strings_proc.stdout.decode(errors="ignore").splitlines()
    filtered = [line for line in lines if "C:\\" in line and ".dll" in line.lower()
                and not any(x in line.lower() for x in ["system32", "syswow64", "winsxs"])]
    return "\n".join(sorted(set(filtered)))
```

### 4.2 Path Traversal – Validate `cache_name`

**Before:**
```python
filepath = os.path.join(CACHE_DIR, f"{cache_name}.json")
```

**After:**
```python
_ALLOWED_CACHES = {"registry_map", "pstree", "cmdline", "netscan", "malfind"}
def query_json_cache(cache_name: str, keyword: str = "") -> str:
    if cache_name not in _ALLOWED_CACHES:
        return f'{"error": "Invalid cache name: {cache_name}"}'
    safe_name = f"{cache_name}.json"
    filepath = os.path.join(CACHE_DIR, safe_name)
    # Ensure the resolved path is still under CACHE_DIR (defence in depth)
    real_path = os.path.realpath(filepath)
    if not real_path.startswith(os.path.realpath(CACHE_DIR)):
        raise PermissionError("Path traversal attempt blocked")
```

### 4.3 Asynchronous Memory Carving with Timeout

**Before:** Blocking `strings` call inside `carve_memory_strings`.

**After (using `asyncio` and `subprocess` timeouts):**
```python
import asyncio

async def carve_memory_strings_async(regex_pattern: str, memory_image_path: str, pid: str = "NONE") -> str:
    # Cache check first (synchronous, fast)
    # ...
    cmd = ["strings", "-a", target_image]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120.0)
    except asyncio.TimeoutError:
        proc.kill()
        return "[!] strings timed out after 120 seconds"
    # Process output with async grep (or use Python filtering)
    ...
```

In `orchestrator.py`, run async tasks concurrently for non‑dependent steps (e.g., `pstree` and `cmdline` can be parallel).

### 4.4 Remove Arbitrary Sleep – Replace with Real API Throttling

**Before:**
```python
print(f"[*] API Governor: Enforcing 4-second execution pace...")
time.sleep(4)
```

**After:** Use token‑bucket or monitor actual API rate limits from Gemini (e.g., `retry_after` header). Only sleep when necessary.

### 4.5 LLM State Machine – Externalise PID Loop

**Before:** Relying on LLM to remember PIDs and loop.

**After:** Let the LLM return a **structured action** and let Python maintain state.

```python
# orchestrator.py – new state class
class InvestigationState:
    def __init__(self):
        self.pending_pids = []      # list of PID strings
        self.current_pid = None
        self.pid_step = None         # e.g., "PSTREE", "CMDLINE", ...
        self.completed_pids = set()
    
    def next_action(self) -> dict:
        if not self.pending_pids:
            return {"action": "request_human_review", "kwargs": {...}}
        if self.current_pid is None:
            self.current_pid = self.pending_pids.pop(0)
            self.pid_step = "PSTREE"
        # map step to required tool call
        ...
```

Then the LLM only fills in gaps (e.g., decide benign/NULL hypothesis) but the iteration is deterministic.

## 5. Prompt Engineering Critique

### What’s Wrong
- **Too rigid, too long** – LLMs ignore or forget parts of long prompts, especially nested instructions. “FOR EVERY SINGLE PID … YOU MUST EXECUTE STEPS A THROUGH E IN EXACT ORDER” is a loop the LLM cannot reliably execute.
- **No context for failure recovery** – The prompt doesn’t tell the LLM what to do if a tool returns an error or unexpected data.
- **Output schema is over‑specified** – `"extracted_target": "Exact numerical PID or Inode"` – but the LLM may hallucinate an inode that doesn’t exist.
- **Cognitive directives (“NULL HYPOTHESIS”)** – These are ambiguous. “Declare the PID benign” – the LLM might do that prematurely.

### How to Make it 10x More Reliable

**Use function‑calling / tool use** instead of forcing JSON output from a free‑text prompt. Gemini supports function declarations. Define each tool as a function with typed parameters. Then the LLM will output structured arguments, and you can enforce validation.

**Separate strategy from execution:**  
The prompt should describe the **goal** (find malicious processes based on RWX memory regions, registry anomalies, and network indicators) and the **available tools**. The actual state machine and loop are implemented in Python. The LLM only answers questions like:
- “Given these malfind results, which PID should I examine first?”
- “Based on the registry carve, is this PID suspicious or benign?”
- “Have I examined all suspect PIDs?”

**Example prompt rewrite (concise, tool‑focused):**

```text
You are a DFIR expert. You have these tools: get_evidence_context, query_json_cache, extract_and_carve_hive, carve_memory_strings, request_human_review.
Follow this algorithm:
1. Call get_evidence_context.
2. Call query_json_cache('malfind', 'PAGE_EXECUTE_READWRITE') to get suspect PIDs.
3. For each PID (start with the smallest):
   a. Query pstree and cmdline.
   b. Query registry_map for SYSTEM and NTUSER (if user exists).
   c. If registry shows anomalous DLLs, mark suspicious.
   d. Query netscan for outbound connections.
   e. If outbound connections exist, carve memory strings for network indicators.
   f. If network indicators show C2, mark as evil.
4. When all PIDs processed, call request_human_review with the findings.
```

But still – **do not rely on the LLM to loop**. Move the loop to Python. Let the LLM evaluate each PID one at a time, and the orchestrator advances the index. That is the only way to guarantee deterministic execution.

---

**Final verdict:** This codebase is a promising research prototype, but it needs a full rewrite to be considered robust, secure, and production‑ready. The refactoring plan above addresses the most critical issues. Implement at least the command injection fixes and state machine externalisation before ever running this on a real case.

# Product Requirements Document (PRD)  
**Project:** Project Find Evil (PFE) – Autonomous DFIR Agent  
**Version:** 0.1.5 (Production‑Hardened Refactor)  
**Date:** 2026‑06‑02  
**Author:** Principal Security Architect  

---

## 1. Executive Summary

Project Find Evil v0.1.4 is a novel autonomous DFIR agent that uses a Large Language Model (Gemini) to orchestrate memory and disk forensics tools (Volatility 3, The Sleuth Kit, `strings`). The current implementation is a functional prototype but suffers from **critical security vulnerabilities** (command injection, path traversal), **unreliable state management** (the LLM is expected to execute deterministic loops it cannot guarantee), and **severe performance bottlenecks** (synchronous carving, arbitrary delays).  

The **way forward** is a complete architectural refactor that moves deterministic control from the LLM to Python, hardens all subprocess interactions, introduces asynchronous I/O and caching, and implements a verifiable state machine. The goal is a **production‑ready agent** that can be deployed in live incident response without exposing the analyst’s workstation to risk.

---

## 2. Current State Analysis (Summary of Critical Deficits)

| Area | Problem | Impact |
|------|---------|--------|
| **Command Injection** | Unsanitized `inode`, `regex_pattern`, `cache_name` passed to `shell=True` subprocesses. | Attacker‑controlled cache data → RCE on forensic host. |
| **Path Traversal** | `cache_name` concatenated into filesystem path without validation. | Read arbitrary files; potential information disclosure. |
| **LLM State Management** | LLM prompt attempts to encode a multi‑step loop; no external state persistence. | Hallucinated PIDs, skipped steps, infinite loops. |
| **Synchronous I/O** | `strings`, `icat`, Volatility plugins block the agent for minutes/hours. | Agent unresponsive; no timeout handling. |
| **Arbitrary Delays** | `time.sleep(4)` after every tool call. | Unnecessary 80+ seconds added to typical investigation. |
| **Cache Races** | Multiple processes write to `CACHE_DIR` without locks. | Corrupted JSON, inconsistent state. |
| **No Error Recovery** | Many `except: pass` or generic `except Exception`. | Silent failures, difficult to debug. |

---

## 3. Target Architecture (v0.1.5)

### 3.1 High‑Level Design

We replace the “LLM as state machine” with a **hybrid controller**:

- **Python Controller (orchestrator)** – Maintains investigation state, iterates over suspect PIDs, calls tools, and handles timeouts/retries.
- **LLM Reasoner** – Only answers high‑level questions:  
  - *Which PID from this malfind list is most suspicious?*  
  - *Given registry carve results, is this benign or malicious?*  
  - *Have we exhausted all evidence?*  
- **Tool Executor (mcp_server)** – Becomes a secure, non‑shell wrapper with input validation, timeouts, and concurrent execution.

### 3.2 Component Diagram

```
[Analyst] ──┬──> [Orchestrator] ──┬──> [LLM Reasoner (Gemini)]
            │                     │         (function calling)
            │                     └──> [State Machine]
            │                              (pending PIDs, current step)
            │
            └──> [Secure Tool Executor] ──> Volatility / SleuthKit / strings
                      (no shell, timeouts, validation)
```

### 3.3 Key Changes

| Old Component | New Component | Change |
|---------------|---------------|--------|
| `agent.py` – System prompt with embedded loop | `prompts/` – Short, function‑calling enabled prompts | Deterministic loop moves to Python. |
| `orchestrator.py` – LLM decides each action | `state_machine.py` – Python enumerates PIDs, calls tools, only consults LLM for classification. | Eliminates hallucination risk. |
| `mcp_server.py` – Unsafe `subprocess.run(shell=True)` | `tool_executor.py` – `subprocess.run` with list args, timeouts, input validation. | No command injection. |
| `extractor.py` – Pre‑extracts everything before agent runs | On‑demand extraction + caching; agent can request specific Volatility plugins. | Faster triage, less waste. |
| `carve_memory_strings` – Runs `strings` on whole memory image | Streaming `strings` with early termination, async I/O, and result caching. | Reduces memory carving from minutes to seconds for repeated queries. |

---

## 4. Phased Refactoring Plan

### Phase 0 – Hardening & Security (Week 1)
- [ ] Remove **all** `shell=True` from `subprocess.run`. Replace with list arguments.
- [ ] Add input validation for `inode` (regex `\d+-\d+-\d+`), `cache_name` (whitelist), `disk_image_path` (resolved absolute path under `EVIDENCE_DIR`).
- [ ] Implement path traversal protection in `query_json_cache` (use `os.path.realpath` check).
- [ ] Add `timeout` parameters to every subprocess call (120s for `strings`, 300s for Volatility, 60s for `icat`).
- [ ] Replace `run_with_timer` with proper `subprocess.run(timeout=…)` and logging.

**Deliverable:** No command injection or path traversal vulnerabilities; all external calls timeout.

### Phase 1 – State Machine Extraction (Week 2)
- [ ] Create `investigation_state.py` with class `InvestigationState`:
  - Attributes: `pending_pids`, `current_pid`, `pid_step`, `results`, `completed_pids`.
  - Methods: `next_action()`, `record_result()`, `advance()`.
- [ ] Modify `orchestrator.py` to instantiate state machine **before** LLM interaction.
- [ ] Remove LLM’s responsibility to iterate PIDs. The LLM only receives one PID at a time and answers:
  - *“Is PID X benign or malicious?”* (yes/no with reasoning)
  - *“Should we carve memory strings for PID X?”* (only if network activity found)
- [ ] Update system prompt to **only** describe tools and the classification task.

**Deliverable:** Deterministic PID iteration; LLM cannot skip or reorder steps.

### Phase 2 – Asynchronous I/O & Concurrency (Week 3)
- [ ] Refactor `carve_memory_strings` to use `asyncio.create_subprocess_exec` with `asyncio.wait_for`.
- [ ] Allow concurrent execution of independent Volatility plugins (e.g., `pstree` and `cmdline`) using `asyncio.gather`.
- [ ] Implement a real token‑bucket rate limiter for Gemini API (respect `retry_after` headers) – remove hardcoded `sleep(4)`.
- [ ] Add file‑based locking (`fcntl` or `portalocker`) for all cache writes.

**Deliverable:** Agent response time improved by ≥60%; no arbitrary delays; cache corruption eliminated.

### Phase 3 – LLM Integration via Function Calling (Week 4)
- [ ] Migrate from JSON‑in‑prompt to **Gemini function calling** (`tools` parameter).
- [ ] Define function declarations:
  ```python
  functions = [
      {"name": "classify_pid", "description": "Determine if PID is suspicious", "parameters": {...}},
      {"name": "request_memory_carve", "description": "Request strings extraction on a PID", "parameters": {...}}
  ]
  ```
- [ ] Orchestrator receives structured function calls instead of raw JSON.
- [ ] Implement fallback: if LLM returns malformed call, retry with lower temperature (0.0 → 0.2).

**Deliverable:** LLM outputs are type‑safe, validated, and cannot hallucinate tool names or parameters.

---

## 5. Detailed Requirements

### 5.1 Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| FR‑01 | Agent must accept a disk image (E01, DD, raw) and/or memory image (raw, mem) as evidence. | P0 |
| FR‑02 | Agent must automatically build required caches (`bodyfile`, `registry_map`) if missing. | P0 |
| FR‑03 | Agent must identify all PIDs with `PAGE_EXECUTE_READWRITE` memory regions using `malfind`. | P0 |
| FR‑04 | For each such PID, agent must (in order): query `pstree`, `cmdline`, registry hive (SYSTEM + NTUSER), `netscan`, and conditionally carve memory strings. | P0 |
| FR‑05 | Agent must classify each PID as **benign** (null hypothesis) or **malicious** based on registry anomalies, outbound network connections, and C2 strings. | P0 |
| FR‑06 | Agent must produce a MITRE ATT&CK report and store IOCs in `ioc_store.json`. | P1 |
| FR‑07 | Agent must allow human override / review at any point (interruptible). | P1 |

### 5.2 Non‑Functional Requirements

| ID | Requirement | Metric |
|----|-------------|--------|
| NFR‑01 | **Security** – No command injection; all external inputs validated against whitelist/regex. | Zero critical/high severity findings in static analysis. |
| NFR‑02 | **Reliability** – Subprocess timeouts prevent infinite hangs; cache writes are atomic. | 100% of tool calls complete or timeout within defined limits. |
| NFR‑03 | **Performance** – Memory carving for a 16GB image with caching: first carve ≤5 min, subsequent carves ≤2 sec. | Benchmarked on standard DFIR workstation (16 cores, 32GB RAM). |
| NFR‑04 | **Concurrency** – Independent Volatility plugins run in parallel. | Time to fetch `pstree` + `cmdline` + `netscan` ≤ time of slowest plugin. |
| NFR‑05 | **Observability** – Structured logging (JSON) with timestamps, tool output, LLM interactions. | Logs can be replayed for debugging. |

---

## 6. Security Requirements (Non‑Negotiable)

- **SR‑01:** No `shell=True` anywhere in production code. Exception only for controlled, non‑user‑input scripts.
- **SR‑02:** All file paths must be resolved via `os.path.realpath` and checked against a base directory (e.g., `EVIDENCE_DIR`, `CACHE_DIR`).
- **SR‑03:** Any string passed as `regex_pattern` to `carve_memory_strings` must be validated: only alphanumeric, underscore, dot, pipe, parentheses – no shell metacharacters.
- **SR‑04:** The agent must run with least privilege (dedicated non‑root user). Volatility and `icat` may require elevated capabilities, but these must be explicitly granted.
- **SR‑05:** API keys (`GEMINI_API_KEY`) must be read from environment or secret manager, never logged.

---

## 7. Performance Requirements & Benchmarks

| Operation | Current (v0.1.4) | Target (v0.1.5) | Improvement |
|-----------|------------------|-----------------|--------------|
| First `carve_memory_strings` (16GB) | ~8‑12 minutes | ≤5 minutes (streaming + early stop) | 2x |
| Repeated `carve_memory_strings` (same query) | ~8‑12 minutes | ≤2 seconds (cache hit) | 240‑360x |
| PID iteration (10 suspect PIDs) | Sequential + sleep(4) per step ≈ 5‑6 minutes | Parallel independent steps ≈ 45 seconds | 6‑8x |
| Agent startup (cache building) | Global `--deep` run = 10+ minutes | On‑demand only = <2 min for minimal required caches | 5x |

---

## 8. LLM Integration Specification (Function Calling)

We will use **Gemini 3.1 Flash Lite** with function declarations. The orchestrator will maintain a conversation context that includes only:

- The current suspect PID.
- The evidence gathered so far (pstree, cmdline, registry carve, netscan).
- A short system prompt: *“You are a DFIR classifier. Based on the evidence, answer: is this PID benign or malicious? Provide one‑sentence reasoning.”*

**Function definitions:**

```json
{
  "name": "classify_pid",
  "description": "Classify a process as benign or malicious based on evidence",
  "parameters": {
    "type": "object",
    "properties": {
      "verdict": { "type": "string", "enum": ["benign", "malicious"] },
      "reasoning": { "type": "string" },
      "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 }
    },
    "required": ["verdict", "reasoning"]
  }
}
```

If `verdict` is `malicious`, the orchestrator will immediately request a memory carve (if not already done) and then call `request_human_review`. If `benign`, it advances to the next PID.

---

## 9. Testing & Validation Strategy

### 9.1 Unit Tests (pytest)
- `test_tool_executor.py` – Validate input sanitisation, timeout behaviour, mock subprocess.
- `test_state_machine.py` – Ensure PID iteration order, completion detection.
- `test_security.py` – Attempt command injection via `inode`, `cache_name`.

### 9.2 Integration Tests
- Use **mock evidence** (small memory image + disk image with known malware indicators).
- Run end‑to‑end investigation; verify report includes correct PID.
- Simulate LLM failures (invalid JSON, timeout) and ensure orchestrator recovers.

### 9.3 Performance Tests (stress_test.py extended)
- Measure carving times with and without cache.
- Run with 50 synthetic PIDs to confirm linear scaling.

### 9.4 Security Tests
- Static analysis: `bandit`, `semgrep` with custom rules against `subprocess` usage.
- Dynamic: Fuzz `cache_name` and `inode` inputs with pathological strings.

---

## 10. Success Metrics (Acceptance Criteria)

| Metric | Target |
|--------|--------|
| **Security** | Zero command injection or path traversal vulnerabilities in final code review. |
| **Determinism** | Given identical evidence, agent produces identical findings (no LLM‑induced variation) – measured over 10 runs. |
| **Performance** | Total investigation time for a 16GB image + 10 suspect PIDs ≤ 12 minutes. |
| **Reliability** | Agent completes successfully on 95% of evidence sets (excluding corrupted images). |
| **Usability** | Analyst can interrupt, override, and receive a human‑readable report in <5 seconds after completion. |

---

## 11. Timeline Estimates

| Phase | Duration | Key Deliverable |
|-------|----------|------------------|
| Phase 0 – Hardening | 5 days | Security‑hardened `tool_executor`, all timeouts added. |
| Phase 1 – State Machine | 5 days | `InvestigationState` integrated; LLM no longer controls loops. |
| Phase 2 – Async I/O | 5 days | Asynchronous carving, parallel plugin execution, rate limiter. |
| Phase 3 – Function Calling | 4 days | Migrate to Gemini function calling; remove JSON parsing. |
| Integration & Testing | 5 days | End‑to‑end tests, performance benchmarks, documentation. |
| **Total** | **24 days** | Production‑ready v0.2.0 candidate. |

---

## 12. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|-------------|
| LLM still hallucinates even with function calling | Medium | High | Use low temperature (0.0), validate responses, retry up to 3 times; fallback to default benign if unrecoverable. |
| Volatility 3 crashes on malformed memory image | High | Medium | Wrap each plugin call in `try/except`, log error, skip plugin, continue investigation. |
| Cache corruption from concurrent writes | Low | Medium | Use file‑locking (`fcntl.flock`) for all JSON writes; write to temporary file then atomic rename. |
| Strings carving on huge memory image exceeds timeout | Medium | Low | Allow user‑configurable timeout; implement early termination after 10,000 matches. |
| Analyst feels loss of control | Medium | Medium | Add interactive mode: after each PID classification, wait for human confirmation (optional flag). |

---

## 13. Next Steps

1. **Approval** – Obtain sign‑off from security & engineering leadership on this PRD.
2. **Implementation** – Begin Phase 0 (Hardening) immediately; create feature branches for each phase.
3. **Review** – After Phase 0, conduct a security audit of all subprocess changes.
4. **Pilot** – Run v0.1.5 on 3 real (anonymised) forensic images to validate against known findings.

---

**Prepared by:** Principal Staff Engineer  
**Version:** 1.0  
**Status:** DRAFT – Awaiting technical review

Kimi

## 1. The Roast (Executive Summary)

This codebase is a textbook example of what happens when a Python script kiddie discovers LLM APIs and `subprocess.call`. It masquerades as a "deterministic state machine" but is actually a probabilistic text generator duct-taped to a shell-injection factory. The architecture is fundamentally broken: the LLM is both the brain and the state machine, yet there is **zero code-level enforcement** of the heuristic loop—just a prayer in the form of a 50-line system prompt. Every subprocess invocation is a remote code execution waiting to happen, and the "caching" strategy is a naive file dump that would collapse under any real forensic load. The fact that `stress_test.py` passes is not a sign of quality; it's a sign that the test is as brittle as the code it validates.

This isn't a DFIR agent; it's a liability generator that happens to run `strings` on memory dumps. The "Universal Forensic Engine" is neither universal nor an engine—it's a loosely coupled collection of blocking shell calls, unvalidated JSON parsing, and exception-swallowing that would make a red teamer weep with joy. The prompt claims the agent "does not skip steps" and "does not make assumptions," yet the code assumes the LLM will never hallucinate an action, assumes `subprocess.run` will never hang, assumes disk images are well-formed, and assumes that `shell=True` with f-string concatenation is acceptable in a security tool. It is not. If this tool were deployed in a production SOC, it would be compromised by its own target before lunch.

---

## 2. Critical Vulnerabilities (P0 & P1)

| Severity | ID | Flaw | Location |
|---|---|---|---|
| **P0** | `SHELL-001` | **Command Injection via `shell=True`**: `carve_memory_strings`, `extract_and_carve_hive`, `generate_bodyfile`, and `run_with_timer` build shell commands using f-strings with unvalidated, LLM-influenced inputs (`memory_image_path`, `disk_image_path`, `inode`, `regex_pattern`). An attacker who can influence the LLM output or cache files gains arbitrary code execution. | `mcp_server.py`, `extractor.py` |
| **P0** | `PATH-001` | **Path Traversal**: `memory_image_path` and `disk_image_path` are passed directly into shell commands without validation. A malicious path like `'; rm -rf /; '` or `../../etc/shadow` is executed verbatim. | `mcp_server.py:carve_memory_strings`, `orchestrator.py:execute_tool` |
| **P0** | `INJ-001` | **Inode Injection**: `extract_and_carve_hive` accepts `inode` as a string and injects it into `icat -i ewf {disk_image_path} {inode}`. No regex validation (`[\d\-]+`) means shell metacharacters pass through. | `mcp_server.py:extract_and_carve_hive` |
| **P1** | `JSON-001` | **Unvalidated LLM Deserialization**: `json.loads(clean_payload)` parses untrusted LLM output with no schema validation. A hallucinated action string or malformed `kwargs` dict crashes the orchestrator or routes to the wrong tool. | `orchestrator.py:main loop` |
| **P1** | `RACE-001` | **File Race Conditions**: `update_ioc_store` and `write_thought_ledger` perform read-modify-write on JSON/text files with no locking (`fcntl`, `filelock`, or atomic writes). Concurrent agent instances will corrupt the IOC store and thought ledger. | `orchestrator.py` |
| **P1** | `EXC-001` | **Silent Failure Swallowing**: `resolve_username_from_pid` and `query_json_cache` contain bare `except Exception: pass` blocks that mask disk failures, JSON corruption, and permission errors. | `mcp_server.py` |
| **P1** | `BLOCK-001` | **Interactive Block in Automation**: `generate_mitre_report` calls `getpass.getpass`, which requires a TTY and blocks indefinitely in headless/containerized environments, breaking CI/CD and autonomous deployment. | `orchestrator.py:generate_mitre_report` |
| **P1** | `REGEX-001` | **Broken Registry Regex**: `prcarve_registry_map` uses regex patterns with trailing `|` (e.g., `r"Windows/System32/config/SYSTEM|"`), which in Python regex means "match SYSTEM OR match empty string." This matches every line, causing the registry map to ingest garbage. | `extractor.py:prcarve_registry_map` |

---

## 3. Performance & Reliability Flaws

- **Blocking Everything**: The entire pipeline is synchronous. Volatility plugins, disk carving, and API calls run sequentially. A single slow `netscan` blocks the whole investigation.
- **Memory Pressure**: `subprocess.run(capture_output=True)` buffers the entire stdout of `strings` and Volatility into RAM. On a 64GB memory image, this will OOM-kill the agent.
- **Fake Timeouts**: `run_with_timer` displays a live timer but does **not** enforce a process timeout. If `icat` or `vol` hangs on a corrupted image, the thread hangs forever and `worker.join()` blocks indefinitely.
- **Hardcoded API Governor**: `time.sleep(4)` between LLM calls is a toy solution. It wastes 4 seconds per step regardless of actual rate limits, and it is not adaptive.
- **O(n) Cache Lookups**: `query_json_cache` loads entire JSON files into memory and performs linear scans. There is no indexing, no SQLite, and no pagination. A 100,000-row `netscan` cache will grind to a halt.
- **Unbounded Subprocess Pipelines**: `strings | grep | grep | sort | head` forks 5 processes and shuffles data through pipes. For multi-GB images, this is CPU-cache-inefficient and wastes context switches.
- **No Max Iteration Guard**: The `while True` in `orchestrator.py` has no iteration ceiling. If the LLM enters a loop (e.g., repeating Step A forever), the agent never terminates.
- **Global State Patching**: `stress_test.py` monkeypatches module globals (`mcp_server.CACHE_DIR = ...`). This is fragile and hides real configuration bugs.

---

## 4. Actionable Refactoring Plan

### Fix 1: Eradicate `shell=True` & F-String Injection

**Before** (`mcp_server.py`):
```python
def carve_memory_strings(regex_pattern: str, memory_image_path: str, pid: str = "NONE") -> str:
    # ...
    cmd = (
        f"strings -a '{target_image}' | "
        f"grep -iE '(https?://...' | "
        f"grep -ivE 'microsoft|...' | "
        f"sort -u | head -n 300"
    )
    output = run_with_timer(cmd, task_name)
```

**After**:
```python
import subprocess
import re
from typing import List

def carve_memory_strings(
    regex_pattern: str, 
    memory_image_path: str, 
    pid: str = "NONE",
    max_results: int = 300,
    timeout_sec: int = 300
) -> str:
    # --- INPUT VALIDATION ---
    if not isinstance(memory_image_path, str) or ".." in memory_image_path:
        return "[!] VALIDATION FAIL: Invalid path."
    if not os.path.isfile(memory_image_path):
        return "[!] VALIDATION FAIL: File not found."
    
    # Resolve target via validated internal helper (no LLM path passthrough)
    target_image = _resolve_memory_target(pid, memory_image_path)
    
    # --- CACHE HIT ---
    carve_cache_dir = os.path.join(CACHE_DIR, "carve_cache")
    os.makedirs(carve_cache_dir, exist_ok=True)
    pattern_hash = hashlib.sha256(f"{regex_pattern}_{target_image}".encode()).hexdigest()
    cache_file = os.path.join(carve_cache_dir, f"strings_{pattern_hash}.txt")
    if os.path.exists(cache_file):
        with open(cache_file, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    # --- SAFE PIPELINE (shell=False logic in Python) ---
    include_re = re.compile(
        r'(https?://|[a-zA-Z0-9.-]+\.(?:org|cn|biz|net|com|xyz|info)|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)',
        re.IGNORECASE
    )
    exclude_re = re.compile(
        r'microsoft|windows|bing|akamai|live\.com|office\.com|skype\.com|'
        r'digicert|verisign|local|w3\.org|127\.0\.0\.1|192\.168\.|10\.|'
        r'outlook|slack|globalsign|quora|reddit|yahoo|youtube|qualtrics|zoom|amazon|adobe|pinterest',
        re.IGNORECASE
    )

    try:
        proc = subprocess.Popen(
            ["strings", "-a", target_image],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        matches: List[str] = []
        if proc.stdout:
            for line in proc.stdout:
                if include_re.search(line) and not exclude_re.search(line):
                    matches.append(line.rstrip("\n"))
                if len(matches) >= max_results:
                    break
        
        proc.wait(timeout=timeout_sec)
        if proc.returncode != 0:
            stderr = proc.stderr.read() if proc.stderr else "unknown"
            return f"[!] strings exited with code {proc.returncode}: {stderr}"
            
        result = "\n".join(matches) if matches else "[*] NULL HYPOTHESIS MET: No external routable indicators found."
        
        with open(cache_file, "w", encoding="utf-8") as f:
            f.write(result)
        return result
        
    except subprocess.TimeoutExpired:
        proc.kill()
        return "[!] TIMEOUT: Memory carving exceeded time limit."
    except Exception as e:
        return f"[!] MEMORY CARVE ERROR: {e}"
```

### Fix 2: Pydantic Schema Enforcement for LLM I/O

**Before** (`orchestrator.py`):
```python
def clean_json_payload(raw_response: str) -> str:
    cleaned = re.sub(r'```json\s*', '', raw_response)
    cleaned = re.sub(r'```\s*', '', cleaned)
    start = cleaned.find('{')
    end = cleaned.rfind('}')
    if start != -1 and end != -1:
        return cleaned[start:end+1]
    return "{}"

# Later...
command_dict = json.loads(clean_payload)
action = command_dict.get("action", "UNKNOWN")
kwargs = command_dict.get("kwargs", {})
```

**After**:
```python
from enum import Enum
from pydantic import BaseModel, Field, field_validator
import json, re

class ActionType(str, Enum):
    GET_EVIDENCE_CONTEXT = "get_evidence_context"
    QUERY_JSON_CACHE = "query_json_cache"
    EXTRACT_AND_CARVE_HIVE = "extract_and_carve_hive"
    CARVE_MEMORY_STRINGS = "carve_memory_strings"
    REQUEST_HUMAN_REVIEW = "request_human_review"

class AgentCommand(BaseModel):
    reasoning: str = Field(..., max_length=300, description="Current step explanation")
    extracted_target: str = Field(default="NONE", pattern=r'^(NONE|[0-9]+)$')
    action: ActionType
    kwargs: dict = Field(default_factory=dict)
    
    @field_validator('kwargs')
    @classmethod
    def validate_kwargs(cls, v: dict, info) -> dict:
        action = info.data.get('action')
        if action == ActionType.QUERY_JSON_CACHE:
            if 'cache_name' not in v or not isinstance(v['cache_name'], str):
                raise ValueError('query_json_cache requires string cache_name')
        elif action == ActionType.EXTRACT_AND_CARVE_HIVE:
            inode = v.get('inode', '')
            if not isinstance(inode, str) or not re.match(r'^[\d\-]+$', inode):
                raise ValueError('inode must be a valid inode string')
            if 'disk_image_path' in v:
                p = v['disk_image_path']
                if not isinstance(p, str) or '..' in p:
                    raise ValueError('disk_image_path must be a safe path')
        elif action == ActionType.CARVE_MEMORY_STRINGS:
            pat = v.get('regex_pattern', '')
            if not isinstance(pat, str) or len(pat) > 200:
                raise ValueError('regex_pattern must be a string under 200 chars')
        return v

def parse_llm_response(raw_response: str) -> AgentCommand:
    cleaned = raw_response.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1]
    if cleaned.endswith("```"):
        cleaned = cleaned.rsplit("\n", 1)[0]
    cleaned = cleaned.strip()
    
    try:
        return AgentCommand.model_validate_json(cleaned)
    except Exception:
        start = cleaned.find('{')
        end = cleaned.rfind('}')
        if start != -1 and end != -1:
            return AgentCommand.model_validate_json(cleaned[start:end+1])
        raise ValueError("Unrecoverable JSON parse failure")
```

### Fix 3: Deterministic State Machine in Code (Not Prompts)

**Before**: The prompt says "You MUST execute Steps A through E" but the code blindly loops on whatever the LLM returns.

**After**:
```python
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional

class Step(Enum):
    ACQUIRE_CONTEXT = 1
    MALFIND_ENUM = 2
    PID_PSTREE = 3
    PID_CMDLINE = 4
    PID_REGISTRY = 5
    PID_NETSCAN = 6
    PID_MEMORY = 7
    PID_EVALUATE = 8
    COMPLETE = 9

@dataclass
class InvestigationState:
    anomalous_pids: List[str] = field(default_factory=list)
    current_pid_idx: int = 0
    step: Step = Step.ACQUIRE_CONTEXT
    findings: List[dict] = field(default_factory=list)
    
    def generate_next_command(self) -> AgentCommand:
        if self.step == Step.ACQUIRE_CONTEXT:
            self.step = Step.MALFIND_ENUM
            return AgentCommand(action=ActionType.GET_EVIDENCE_CONTEXT, reasoning="Acquiring evidence context.")
        
        if self.step == Step.MALFIND_ENUM:
            self.step = Step.PID_PSTREE
            return AgentCommand(
                action=ActionType.QUERY_JSON_CACHE,
                kwargs={"cache_name": "malfind", "keyword": "PAGE_EXECUTE_READWRITE"},
                reasoning="Enumerating anomalous RWX PIDs."
            )
        
        if self.current_pid_idx >= len(self.anomalous_pids):
            self.step = Step.COMPLETE
            return AgentCommand(action=ActionType.REQUEST_HUMAN_REVIEW, kwargs={"keyword": "INVESTIGATION_COMPLETE"})
        
        pid = self.anomalous_pids[self.current_pid_idx]
        transition = {
            Step.PID_PSTREE: (ActionType.QUERY_JSON_CACHE, {"cache_name": "pstree", "keyword": pid}, f"Step A: pstree for PID {pid}"),
            Step.PID_CMDLINE: (ActionType.QUERY_JSON_CACHE, {"cache_name": "cmdline", "keyword": pid}, f"Step B: cmdline for PID {pid}"),
            Step.PID_REGISTRY: (ActionType.QUERY_JSON_CACHE, {"cache_name": "registry_map", "keyword": pid}, f"Step C: registry for PID {pid}"),
            Step.PID_NETSCAN: (ActionType.QUERY_JSON_CACHE, {"cache_name": "netscan", "keyword": pid}, f"Step D: netscan for PID {pid}"),
            Step.PID_MEMORY: (ActionType.CARVE_MEMORY_STRINGS, {"regex_pattern": "NETWORK"}, f"Step E: memory carve for PID {pid}"),
        }
        
        if self.step in transition:
            action, kwargs, reason = transition[self.step]
            self.step = Step.PID_EVALUATE if self.step == Step.PID_MEMORY else Step(self.step.value + 1)
            return AgentCommand(action=action, kwargs=kwargs, reasoning=reason, extracted_target=pid)
        
        if self.step == Step.PID_EVALUATE:
            # Null hypothesis evaluation happens here based on stored results
            self.current_pid_idx += 1
            self.step = Step.PID_PSTREE
            return self.generate_next_command()
        
        raise RuntimeError(f"Unhandled state: {self.step}")
```

### Fix 4: Async API Governor & Subprocess Timeouts

**Before**:
```python
def safe_api_call(chat_session, prompt: str, max_retries: int = 5) -> str:
    for attempt in range(max_retries):
        try:
            response = chat_session.send_message(prompt)
            return response.text
        except Exception as e:
            delay = 2 * (2 ** attempt)
            time.sleep(delay)
    return "{}"

# In main loop:
time.sleep(4)
```

**After**:
```python
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

class APIGovernor:
    def __init__(self, rpm_limit: int = 15):
        self.min_interval = 60.0 / rpm_limit
        self.last_call = 0.0
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        async with self._lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self.last_call
            if elapsed < self.min_interval:
                await asyncio.sleep(self.min_interval - elapsed)
            self.last_call = asyncio.get_event_loop().time()

@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=60),
    retry=retry_if_exception_type((ConnectionError, TimeoutError))
)
async def safe_api_call(chat_session, prompt: str, governor: APIGovernor) -> str:
    await governor.acquire()
    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(None, lambda: chat_session.send_message(prompt))
    return response.text
```

### Fix 5: Registry Regex & Exclude Logic

**Before** (`extractor.py`):
```python
targets = {
    "SYSTEM": "Windows/System32/config/SYSTEM|",
    "SOFTWARE": "Windows/System32/config/SOFTWARE|",
    "NTUSER": "Users/.*/NTUSER.DAT|"
}
exclude = re.compile(r"default|public|Windows.old", re.IGNORECASE)
```

**After**:
```python
targets = {
    "SYSTEM": r"Windows/System32/config/SYSTEM\|",
    "SOFTWARE": r"Windows/System32/config/SOFTWARE\|",
    "NTUSER": r"Users/[^/]+/NTUSER\.DAT\|"
}
# Exclude specific system profiles, not any path containing the word "default"
exclude = re.compile(r"/(default|public|Windows\.old)/", re.IGNORECASE)
```

---

## 5. Prompt Engineering Critique

### Current Prompt Analysis

The existing prompt in `agent.py` is a **failure on three levels**:

1. **Length & Attention Decay**: It is ~60 lines of dense procedural text. Gemini Flash-Lite has a limited attention window; it will ignore the middle third. The "STRICTLY FORBIDDEN" clause is buried in the middle and will be forgotten.
2. **The Determinism Lie**: It claims the agent is a "deterministic state machine" that "does not skip steps." This is a lie. LLMs are probabilistic. The prompt is attempting to do the job of code, and it will fail under edge cases, context window pressure, or adversarial inputs.
3. **No Schema or Few-Shot**: The prompt describes a JSON format but provides no schema, no field types, and no examples. The model has to infer the exact structure from a wall of text.

### Production-Grade Prompt Rewrite

```text
You are the Universal Forensic Engine (UFE). Investigate Windows memory/disk images for malware.

RULES:
1. Output ONLY a JSON object. No markdown fences, no prose.
2. Do not invent actions. Use only the actions listed below.
3. Follow the investigation protocol exactly.

JSON SCHEMA:
{
  "reasoning": "string (max 200 chars). State current PID and step.",
  "extracted_target": "string: PID number or 'NONE'",
  "action": "enum: get_evidence_context | query_json_cache | extract_and_carve_hive | carve_memory_strings | request_human_review",
  "kwargs": "object. Exact parameters for the chosen action."
}

ACTIONS:
- get_evidence_context: {}
- query_json_cache: {"cache_name": "pstree|cmdline|registry_map|netscan|malfind", "keyword": "string"}
- extract_and_carve_hive: {"inode": "string", "disk_image_path": "string (optional)"}
- carve_memory_strings: {"regex_pattern": "NETWORK or custom regex", "memory_image_path": "string (optional)"}
- request_human_review: {"keyword": "summary string"}

INVESTIGATION PROTOCOL:
1. Call get_evidence_context.
2. Query malfind with keyword 'PAGE_EXECUTE_READWRITE' to get anomalous PIDs.
3. For EACH PID in order:
   A. Query pstree for the PID.
   B. Query cmdline for the PID.
   C. Query registry_map for the PID (or 'SYSTEM'), then extract_and_carve_hive.
   D. Query netscan for the PID.
   E. Call carve_memory_strings with regex_pattern "NETWORK".
   F. If hive is clean AND network indicators are benign, declare Null Hypothesis and proceed to next PID.
4. After all PIDs, call request_human_review.

EXAMPLE:
Input: [SYSTEM DATA: get_evidence_context] {"MODE": "HYBRID"}
Output: {"reasoning":"Context acquired. Mode HYBRID.","extracted_target":"NONE","action":"query_json_cache","kwargs":{"cache_name":"malfind","keyword":"PAGE_EXECUTE_READWRITE"}}

Input: [SYSTEM DATA: query_json_cache] PIDs: 1234, 5678
Output: {"reasoning":"Anomalous PIDs found. Starting with 1234.","extracted_target":"1234","action":"query_json_cache","kwargs":{"cache_name":"pstree","keyword":"1234"}}
```

### Why This Is Better

- **Schema-First**: The model knows the exact shape of the output, reducing hallucinated fields.
- **Few-Shot Examples**: Two examples anchor the model to the correct format.
- **Shorter**: ~30 lines vs. 60. Less chance of attention decay.
- **Honest**: It says "Follow the protocol" rather than claiming to be a deterministic CPU. The actual enforcement is handled by the Pydantic state machine in code (Fix 3).
- **Action Enum**: Explicitly lists valid actions, preventing the LLM from inventing `read_dfir_playbook` (which is imported in `orchestrator.py` but not in the prompt's allowed actions—another bug in the original).

Project Find Evil — v0.1.5 Production-Grade Autonomous DFIR Engine
Document Version: 1.0
Status: DRAFT — Ready for Engineering Review
Date: 2026-06-02
Classification: Internal — Engineering & Architecture
Author: Principal Staff Engineer / Security Architect
1. Executive Summary
Project Find Evil v0.1.4 is a promising proof-of-concept that demonstrates the viability of LLM-orchestrated autonomous digital forensics. However, the current codebase is architecturally unsound, contains critical security vulnerabilities, and lacks the determinism, resilience, and performance characteristics required for production deployment in a Security Operations Center (SOC) or incident response retainer.
This PRD defines v0.1.5: a ground-up architectural refactor that preserves the core heuristic concept while replacing every fragile subsystem with a production-grade equivalent.
The v0.1.5 engine will be:
Deterministic by design: The investigation protocol is enforced by a finite state machine (FSM) written in code, not by a system prompt.
Secure by default: All subprocess execution uses shell=False, strict input validation via Pydantic, and path sandboxing. No user-supplied or LLM-generated string ever reaches a shell interpreter.
Resilient under load: Asynchronous I/O, subprocess timeouts, circuit breakers, and graceful degradation chains ensure the agent survives corrupted evidence, missing binaries, and API outages.
Observable and auditable: Every cognitive step, tool invocation, and state transition is immutably logged with cryptographic integrity checks.
Performance-scalable: Streaming data pipelines, SQLite-backed indexing, and multiprocessing for CPU-bound carving tasks eliminate the blocking I/O and memory pressure bottlenecks of v0.1.4.
2. Problem Statement: Why v0.1.4 Cannot Ship
The v0.1.4 codebase exhibits five classes of fatal flaws that categorically prohibit production use:
2.1 Security — Critical (P0)
The system is a command-injection factory. shell=True is used in extractor.py, mcp_server.py, and orchestrator.py with f-string concatenation of LLM-influenced inputs (memory_image_path, disk_image_path, inode, regex_pattern). An adversary who poisons a cache file or influences LLM output gains arbitrary code execution with the privileges of the DFIR analyst. There is no input validation, no path sandboxing, and no principle of least privilege.
2.2 Determinism — Critical (P0)
The "mandatory per-PID heuristic loop" is described in a system prompt but is not enforced in code. The orchestrator blindly trusts whatever JSON the LLM emits. The LLM can skip steps, repeat steps indefinitely, hallucinate non-existent actions (e.g., read_dfir_playbook), or enter infinite loops. There is no max-iteration guard, no step validation, and no recovery mechanism.
2.3 Performance & Reliability — High (P1)
Every operation is synchronous and blocking. A 64GB memory image will OOM-kill the agent because subprocess.run(capture_output=True) buffers the entire stdout into RAM. Subprocesses have no timeout enforcement (run_with_timer displays a timer but does not kill the process). The 4-second hardcoded time.sleep(4) API governor wastes analyst time and is not adaptive to actual rate limits.
2.4 Data Integrity — High (P1)
The cache layer is a collection of unvalidated JSON text files written with non-atomic read-modify-write patterns. Concurrent agent instances, crashes, or disk-full conditions will corrupt the IOC store and thought ledger. There is no file locking, no journaling, and no cache invalidation strategy.
2.5 Error Handling — Medium (P2)
Exceptions are swallowed silently with bare except Exception: pass blocks. The pure-Python MBR/GPT fallback parser lacks bounds checking and will crash on malformed sector data. The getpass.getpass call in generate_mitre_report blocks indefinitely in headless environments, breaking CI/CD and containerized deployments.
3. Goals & Non-Goals
3.1 Goals (In Scope)
Table
ID	Goal	Priority
G1	Code-Level Determinism: Implement a finite state machine (FSM) that enforces the heuristic loop regardless of LLM output.	P0
G2	Zero Shell Injection: Eradicate all shell=True usage. All subprocess execution must use shell=False with validated argument lists.	P0
G3	Schema-Enforced LLM I/O: Use Pydantic v2 to validate, parse, and coerce all LLM output into strictly typed AgentCommand objects.	P0
G4	Async & Streaming Architecture: Replace blocking I/O with asyncio. Implement streaming subprocess stdout consumption to eliminate OOM risk.	P1
G5	Atomic & Indexed Caching: Replace raw JSON file dumps with SQLite for structured cache data and atomic file writes for binary artifacts.	P1
G6	Subprocess Timeouts & Circuit Breakers: Every external tool invocation must have a configurable timeout and a fallback chain.	P1
G7	Immutable Audit Ledger: Replace thoughts.txt with a cryptographically chained, append-only log (e.g., BLAKE3 hashes linking entries).	P1
G8	Modular Tool Interface: Define a formal Tool protocol/ABC so that new forensics plugins can be added without modifying the orchestrator.	P2
G9	Comprehensive Test Matrix: Achieve >90% unit test coverage, property-based testing for input validation, and integration tests with mocked Volatility/sleuthkit binaries.	P2
3.2 Non-Goals (Out of Scope for v0.1.5)
Distributed/multi-node forensics: The engine remains single-node. Clustering is a v0.2.0 consideration.
Real-time streaming memory analysis: We still operate on captured images, not live memory streams.
GUI/Web dashboard: v0.1.5 is CLI-first. A web frontend is a separate product line.
Multi-LLM provider abstraction: We target Gemini API specifically, but the gateway layer should be designed for future portability.
4. Architecture Overview
4.1 High-Level Component Diagram
plain
┌─────────────────────────────────────────────────────────────────────────┐
│                         INVESTIGATOR / CLI                               │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    ORCHESTRATOR (asyncio event loop)                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐  │
│  │  State Machine  │  │  LLM Gateway    │  │  Telemetry & Audit      │  │
│  │  (Finite)       │  │  (Pydantic/     │  │  (Immutable Ledger)     │  │
│  │                 │  │   Retry/Async)  │  │                         │  │
│  └────────┬────────┘  └────────┬────────┘  └─────────────────────────┘  │
│           │                    │                                         │
│           └────────────────────┘                                         │
│                    │                                                     │
│                    ▼                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    TOOL SANDBOX                                   │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │   │
│  │  │ Volatility│ │ Sleuthkit│ │  Strings │ │  Custom Carvers  │   │   │
│  │  │  Plugin   │ │  Tools   │ │  Pipeline│ │  (Python native) │   │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                    │                                                     │
│                    ▼                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    DATA LAYER                                     │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │   │
│  │  │  SQLite      │  │  File Cache  │  │  Evidence Registry   │   │   │
│  │  │  (Indexed)   │  │  (Atomic)    │  │  (Validation)        │   │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
4.2 Design Principles
Prompts Describe, Code Enforces: The LLM prompt explains the investigation protocol, but the StateMachine class is the sole authority on what step comes next. The LLM provides reasoning and suggestions; the orchestrator decides actions.
Fail Secure, Not Fail Silent: Every error must be logged, categorized, and surfaced. Silent pass blocks are forbidden by linting policy.
No String Interpolation into Commands: All external tool arguments are passed as lists. Paths are resolved and validated against an evidence sandbox directory before execution.
Immutable by Default: Cache writes are atomic (write to temp, fsync, rename). Audit logs are append-only with hash chaining.
Resource Boundaries: Every subprocess has a timeout_sec, max_memory_mb, and max_output_lines. Exceeding any boundary triggers a controlled termination.
5. Detailed Requirements
5.1 Security Hardening (P0)
REQ-SEC-001: Subprocess Execution Model
Current State: subprocess.run(cmd, shell=True, capture_output=True, text=True) with f-string command building.
Target State: All subprocess calls must use subprocess.Popen or subprocess.run with shell=False and a validated list of arguments.
Specification:
A SafeSubprocessRunner class must be created that wraps all external tool execution.
The runner must accept a command: List[str] and env: Optional[Dict[str, str]].
All path arguments must be validated via _validate_evidence_path(path: str) -> Path before execution.
The validation function must:
Resolve the path to an absolute path.
Ensure the path is within EVIDENCE_DIR or CACHE_DIR (configurable sandbox root).
Reject paths containing null bytes, control characters, or shell metacharacters (;, |, &, $, `, etc.).
Reject symlinks that point outside the sandbox.
Exception: None. Even "trusted" internal paths must be validated.
Example Implementation:
Python
from pathlib import Path
from typing import List, Optional
import subprocess
import os

class SafeSubprocessRunner:
    SANDBOX_ROOTS: List[Path] = []

    @classmethod
    def configure_sandbox(cls, roots: List[str]):
        cls.SANDBOX_ROOTS = [Path(r).resolve() for r in roots]

    @classmethod
    def validate_path(cls, path_str: str) -> Path:
        if not isinstance(path_str, str):
            raise TypeError("Path must be a string")
        if "\x00" in path_str:
            raise ValueError("Path contains null bytes")
        # Reject shell metacharacters
        if any(c in path_str for c in ";|&$`\n\r"):
            raise ValueError("Path contains shell metacharacters")

        p = Path(path_str).resolve()
        # Check symlink traversal
        real_p = p.resolve(strict=False)

        if not any(str(real_p).startswith(str(root)) for root in cls.SANDBOX_ROOTS):
            raise ValueError(f"Path {real_p} is outside evidence sandbox")
        return p

    def run(
        self,
        command: List[str],
        timeout_sec: int = 300,
        max_output_mb: int = 512,
        cwd: Optional[str] = None
    ) -> subprocess.CompletedProcess:
        if not command:
            raise ValueError("Empty command")

        # Validate all arguments that look like paths
        for arg in command:
            if isinstance(arg, str) and (arg.startswith("/") or arg.startswith("./")):
                self.validate_path(arg)

        env = os.environ.copy()
        env["PATH"] = "/usr/bin:/bin:/usr/local/bin"  # Restrict PATH

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                cwd=cwd,
                env=env,
                shell=False
            )
            # Truncate oversized output to prevent memory pressure
            max_chars = max_output_mb * 1024 * 1024
            if len(result.stdout) > max_chars:
                result.stdout = result.stdout[:max_chars] + "\n[!] OUTPUT TRUNCATED"
            return result
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"Subprocess timed out after {timeout_sec}s: {command[0]}") from e
REQ-SEC-002: LLM Output Sanitization
Current State: json.loads(clean_payload) with no schema validation.
Target State: All LLM output must pass through a Pydantic v2 model before any tool is invoked.
Specification:
Define AgentCommand as a Pydantic BaseModel with strict field validation.
action must be a Literal or Enum of permitted actions only.
kwargs must be a Dict[str, Any] that is validated by action-specific sub-models.
If validation fails, the orchestrator must enter a RECOVERY state that sends a corrective prompt to the LLM ("Invalid action. Valid actions are: ...") rather than crashing or executing a malformed command.
Implement a max_retries=3 loop for validation failures before escalating to request_human_review with an error classification.
REQ-SEC-003: Input Validation for Forensic Identifiers
Current State: inode is passed as a raw string into icat.
Target State: All forensic identifiers must match strict regex patterns.
Specification:
inode: Must match ^[\d\-]+$ (digits and hyphens only).
pid: Must match ^\d+$ and be within a reasonable range (1 to 2^22).
regex_pattern: Must be a string under 200 characters. Must not contain null bytes or unprintable characters. Must be validated as a compilable Python regex before use in re.compile() to prevent ReDoS.
cache_name: Must be a Literal from the set of known caches.
REQ-SEC-004: Environment Isolation
Current State: The agent runs with the analyst's full user privileges and unrestricted environment.
Target State: The agent should support running in a restricted environment.
Specification:
Support execution inside a Linux namespace (optional) or container with read-only evidence mounts.
Drop unnecessary environment variables before subprocess execution (restrict PATH, clear LD_PRELOAD, etc.).
Evidence directories should be mounted read-only where possible; cache directories are write-only to the agent.
5.2 Deterministic Orchestration (P0)
REQ-ORCH-001: Finite State Machine (FSM) Implementation
Current State: The investigation loop is a while True that trusts the LLM to return the correct next action.
Target State: A formal FSM defines all valid states and transitions.
Specification:
Implement InvestigationStateMachine as a pure Python class with no LLM dependency.
States:
S0_INIT
S1_ACQUIRE_CONTEXT
S2_ENUMERATE_PIDS (queries malfind)
S3_PID_PSTREE (per-PID)
S4_PID_CMDLINE
S5_PID_REGISTRY
S6_PID_HIVE_CARVE
S7_PID_NETSCAN
S8_PID_MEMORY_CARVE
S9_PID_EVALUATE (Null Hypothesis check)
S10_COMPLETE
Transitions are deterministic functions of (current_state, tool_result).
The LLM is only consulted for:
Generating the reasoning string for the current step.
Evaluating the Null Hypothesis at S9 (interpreting clean vs. dirty indicators).
Generating the final request_human_review summary.
The orchestrator may override the LLM's requested action if it violates the FSM transition table. In such cases, the LLM's action is treated as a "suggestion" and the orchestrator enforces the correct action, logging the divergence.
REQ-ORCH-002: Max Iteration & Loop Detection
Current State: No limit on loop iterations.
Target State: Hard limits and anomaly detection.
Specification:
MAX_INVESTIGATION_STEPS = 200 (configurable). If exceeded, the orchestrator force-transitions to S10_COMPLETE with a LOOP_DETECTED error code.
Maintain a step_history: List[Tuple[State, str]] (state + extracted_target). If the same (state, target) pair appears 3 times within 10 steps, trigger LOOP_DETECTED.
If the LLM requests the same action with the same kwargs twice in a row, the second request is intercepted and the cached result is returned without tool re-execution (deduplication guard).
REQ-ORCH-003: Action Whitelist Enforcement
Current State: The orchestrator has an if/elif chain that falls through to "Illegal Action Requested".
Target State: Actions are dispatched via a registry pattern with strict whitelist enforcement.
Specification:
Implement ToolRegistry that maps ActionType to Tool instances.
Only registered tools can be invoked. Any unregistered action results in an immediate RECOVERY state transition.
The read_dfir_playbook function (currently imported but not in the LLM prompt's action list) must either be registered as a formal tool or removed.
5.3 LLM Gateway & Reliability (P0/P1)
REQ-LLM-001: Pydantic Schema Enforcement
Current State: Regex-based JSON extraction from markdown-fenced LLM output.
Target State: Structured output via Gemini's native JSON mode + Pydantic validation.
Specification:
Continue using response_mime_type="application/json" but add response_schema=AgentCommand.model_json_schema() if the SDK supports it (Gemini 1.5+ supports constrained generation).
If constrained generation is unavailable, use the prompt-based schema approach with a strict parse_llm_response function that attempts Pydantic validation, then regex extraction, then recovery.
The AgentCommand schema must be injected into the system prompt as a JSON Schema block (not just prose description).
REQ-LLM-002: Adaptive API Governor
Current State: time.sleep(4) regardless of actual rate limit status.  Target State: Token-bucket or adaptive backoff governor.
Specification:
Implement APIGovernor using asyncio and a token-bucket algorithm.
Configurable requests_per_minute (default: 15 for Gemini Flash-Lite free tier, 60 for paid).
If a 429 Too Many Requests is received, extract the Retry-After header and use exponential backoff with jitter.
Governor must be shared across all concurrent investigation tasks (singleton per process).
REQ-LLM-003: Hallucination Detection & Recovery
Current State: No detection of LLM hallucinations (e.g., inventing actions, skipping steps).  Target State: Divergence detection and corrective feedback.
Specification:
After parsing AgentCommand, the orchestrator checks action against the FSM's expected action for the current state.
If the LLM suggests an action that is not the expected next step, log a HALLUCINATION event and send a corrective system message:
plain
[CORRECTION] Expected next action: {expected_action}. 
Your suggested action {suggested_action} is not valid at this state. 
Please output the correct JSON for the expected action.
If the LLM hallucinates a kwargs key that is not in the action's schema, strip it and log KWARG_PRUNED.
If the LLM outputs markdown fences (```json), the parser strips them automatically without penalizing the model.
REQ-LLM-004: Prompt Engineering Specification
Current State: A 60-line wall of procedural text with no schema, no examples, and false determinism claims.  Target State: A concise, schema-first, few-shot prompt with honest probabilistic framing.
Specification:
Length: Maximum 40 lines or 800 tokens. Attention decay research shows mid-prompt instructions are ignored.
Structure:
Role definition (1 line).
Output rules (3 bullets).
JSON Schema (injected dynamically from AgentCommand.model_json_schema()).
Valid actions enum (1 line per action).
Investigation protocol (numbered list, 10 items max).
Two few-shot examples (input/output pairs).
Tone: Do not claim the LLM is a "deterministic state machine." Instead: "You are a heuristic advisor. The system will enforce the protocol. Your job is to provide reasoning and select the correct action from the allowed list."
Dynamic Injection: The prompt must be templated so that the current FSM state, available caches, and investigation progress are injected as context before each turn.
5.4 Performance & Concurrency (P1)
REQ-PERF-001: Async Subprocess Streaming
Current State: subprocess.run(capture_output=True) blocks the event loop and buffers everything into RAM.  Target State: Streaming, async subprocess execution.
Specification:
Use asyncio.create_subprocess_exec for all external tools.
Consume stdout via async for line in process.stdout: with a line-by-line generator.
Apply filters (regex, grep logic) in Python as lines are streamed, rather than piping through 5 shell processes.
Maintain a max_lines cap (e.g., 10,000 lines) to prevent runaway output from consuming memory.
For tools that require complex pipelines (e.g., strings | grep | sort), replace with Python-native streaming:
Python
async def stream_strings(image_path: Path, filters: List[re.Pattern], max_lines: int = 10000):
    proc = await asyncio.create_subprocess_exec(
        "strings", "-a", str(image_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    count = 0
    async for line in proc.stdout:
        decoded = line.decode("utf-8", errors="ignore").rstrip("\n")
        if all(f.search(decoded) for f in filters):
            yield decoded
            count += 1
            if count >= max_lines:
                proc.kill()
                break
    await proc.wait()
REQ-PERF-002: SQLite-Backed Cache with Indexing
Current State: JSON text files loaded entirely into memory for every query.  Target State: SQLite for structured data, file system for blobs.
Specification:
Create evidence_cache.db with tables:
sql
CREATE TABLE cache_entries (
    id INTEGER PRIMARY KEY,
    cache_name TEXT NOT NULL,
    keyword TEXT,
    payload BLOB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    UNIQUE(cache_name, keyword)
);
CREATE INDEX idx_cache_lookup ON cache_entries(cache_name, keyword);
CREATE INDEX idx_cache_expiry ON cache_entries(expires_at);
query_json_cache becomes a SQL query with LIKE or exact match, returning paginated results.
Large binary outputs (memory dumps, carved hives) remain as files in CACHE_DIR, but their metadata (path, hash, size, created_at) is tracked in SQLite.
Implement cache TTL: netscan and malfind caches expire after 24 hours by default (evidence is static, but re-processing may be needed).
REQ-PERF-003: Multiprocessing for CPU-Bound Carving
Current State: Single-threaded execution.  Target State: Parallel carving where safe.
Specification:
Use concurrent.futures.ProcessPoolExecutor for CPU-bound tasks like:
Pure-Python MBR/GPT parsing.
String extraction from large memory images (partition the image into chunks and carve in parallel, then merge results).
The main orchestrator remains async (asyncio), but dispatches CPU-bound work to the process pool via loop.run_in_executor().
Max workers: min(4, os.cpu_count()) to avoid overwhelming the forensic workstation.
REQ-PERF-004: Intelligent Cache Pre-warming
Current State: extractor.py runs all plugins sequentially in build_environment().  Target State: Parallel pre-warming with dependency resolution.
Specification:
pstree and cmdline have no dependencies and can run in parallel.
malfind and netscan are independent and can run in parallel.
registry_map depends on bodyfile.txt generation.
Implement a DAG (Directed Acyclic Graph) of extraction tasks and execute independent tasks concurrently using asyncio.gather().
5.5 Error Handling & Resilience (P1)
REQ-ERR-001: Structured Exception Hierarchy
Current State: Generic Exception catching everywhere.  Target State: Hierarchical, typed exceptions.
Specification:
Python
class DFIRError(Exception):
    """Base class for all DFIR agent errors."""
    pass

class ValidationError(DFIRError):
    """Input validation failed (security or format)."""
    pass

class ToolExecutionError(DFIRError):
    """External tool (vol, icat, strings) failed."""
    def __init__(self, message, tool_name, return_code, stderr):
        super().__init__(message)
        self.tool_name = tool_name
        self.return_code = return_code
        self.stderr = stderr

class TimeoutError(DFIRError):
    """Operation exceeded time budget."""
    pass

class CacheError(DFIRError):
    """Cache read/write failure."""
    pass

class LLMError(DFIRError):
    """LLM API failure or hallucination."""
    pass

class StateMachineError(DFIRError):
    """Invalid state transition attempted."""
    pass
Every tool wrapper must catch subprocess.CalledProcessError, subprocess.TimeoutExpired, and FileNotFoundError, then re-raise as the appropriate DFIRError subclass with full context.
The orchestrator's main loop catches DFIRError and transitions to RECOVERY or COMPLETE based on severity.
REQ-ERR-002: Fallback Chain Specification
Current State: Fallbacks are ad-hoc and sometimes recursive (e.g., extract_and_carve_hive has two nested directory walk fallbacks).  Target State: Explicit, ordered fallback chains.
Specification:
For each tool, define a FallbackChain: List[Callable].
Example for hive carving:
Primary: icat -i ewf {disk} {inode} (requires disk image and sleuthkit).
Secondary: Search EVIDENCE_DIR for pre-extracted hive files by name.
Tertiary: Return NULL_HYPOTHESIS (hive unavailable, proceed on memory evidence only).
Each fallback attempt is logged with its outcome. If all fail, the tool returns a structured error object, not a string containing [!].
REQ-ERR-003: Subprocess Timeout Enforcement
Current State: run_with_timer displays a timer but does not kill the process.  Target State: Hard timeouts with SIGKILL escalation.
Specification:
Default timeout: 300 seconds (5 minutes) for Volatility plugins, 60 seconds for cache queries, 600 seconds for memory carving.
On timeout: send SIGTERM, wait 5 seconds, then SIGKILL.
The timer thread must be replaced with asyncio.wait_for() or subprocess.run(timeout=...).
REQ-ERR-004: Health Checks & Graceful Degradation
Target State: The agent must self-diagnose its environment before starting.
Specification:
On startup, run EnvironmentHealthCheck:
Verify vol binary exists and responds to --help.
Verify icat, fls, mmls exist (if disk mode is active).
Verify strings exists.
Verify GEMINI_API_KEY is set and API is reachable (lightweight ping).
Verify evidence paths are readable and cache paths are writable.
If a required binary is missing, log a warning and disable the affected mode (e.g., fall back from HYBRID to MEMORY_ONLY or DISK_ONLY). Do not crash.
5.6 Data Layer & Caching (P1)
REQ-DATA-001: Atomic File Operations
Current State: open(path, "w") followed by json.dump() — non-atomic and corruptible on crash.  Target State: Atomic writes via temp-and-rename.
Specification:
All file writes must use atomic_write(path, content):
Python
import tempfile
import os

def atomic_write(target_path: str, content: str):
    dir_name = os.path.dirname(target_path)
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".tmp_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(fd)
        os.rename(tmp_path, target_path)
    except Exception:
        os.unlink(tmp_path)
        raise
This applies to thoughts.txt, ioc_store.json, cache files, and report generation.
REQ-DATA-002: File Locking for Concurrent Access
Current State: No locking. Concurrent instances will corrupt shared files.  Target State: Advisory file locking.
Specification:
Use filelock (Python library) or fcntl (Unix) for cross-platform locking.
The IOC store and thought ledger must acquire an exclusive lock during read-modify-write operations.
SQLite handles concurrency natively via WAL mode (Write-Ahead Logging), which must be enabled.
REQ-DATA-003: Cache Invalidation Strategy
Target State: Explicit TTL and versioning.
Specification:
Each cache entry has an expires_at timestamp.
A background task (or startup check) purges expired entries.
If the evidence file modification time (mtime) changes, all caches derived from that file are invalidated automatically.
Cache entries are versioned by a hash of the source evidence file (e.g., blake3(evidence_file)). If the evidence changes, the version hash mismatch triggers cache rebuild.
5.7 Observability & Audit (P1)
REQ-OBS-001: Immutable Thought Ledger
Current State: thoughts.txt is a plain text file with no integrity protection.  Target State: Cryptographically chained, append-only log.
Specification:
Replace thoughts.txt with a sequence of JSON Lines (.jsonl) entries.
Each entry contains:
JSON
{
  "seq": 42,
  "timestamp": "2026-06-02T13:45:00Z",
  "phase": "TX_OUTBOUND",
  "component": "LLM_GATEWAY",
  "details": "...",
  "prev_hash": "sha256_of_previous_entry",
  "entry_hash": "sha256_of_this_entry_minus-entry_hash-field"
}
The hash chain ensures tamper-evidence. If an entry is modified, the chain breaks.
Provide a verify_ledger() function that checks the entire chain on startup.
REQ-OBS-002: Structured Logging
Target State: JSON-structured logs to stderr and/or file.
Specification:
Use Python's logging module with a JSONFormatter.
Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL.
Every tool invocation logs: tool_name, args (sanitized), start_time, end_time, return_code, output_size_bytes, timeout_sec.
Every LLM call logs: prompt_tokens (if available), response_tokens, latency_ms, action_requested, validation_result.
Every state transition logs: from_state, to_state, trigger, pid (if applicable).
REQ-OBS-003: Metrics Exposure
Target State: Prometheus-compatible metrics endpoint (optional but recommended).
Specification:
Expose counters for:
ufe_investigations_total
ufe_steps_total (labeled by state)
ufe_tool_errors_total (labeled by tool and error type)
ufe_llm_hallucinations_total
ufe_cache_hits_total / ufe_cache_misses_total
ufe_api_latency_seconds (histogram)
Expose gauges for:
ufe_active_investigations
ufe_cache_size_bytes
5.8 Modularity & Tool Interface (P2)
REQ-MOD-001: Tool Protocol (ABC)
Target State: New tools can be added without touching the orchestrator.
Specification:
Python
from abc import ABC, abstractmethod
from typing import Dict, Any
from pydantic import BaseModel

class ToolInput(BaseModel):
    pass

class ToolOutput(BaseModel):
    success: bool
    data: Any
    error_message: Optional[str] = None
    execution_time_ms: int

class Tool(ABC):
    name: str
    required_binaries: List[str] = []

    @abstractmethod
    async def execute(self, input_data: ToolInput) -> ToolOutput:
        pass

    def validate_environment(self) -> List[str]:
        """Return list of missing dependencies."""
        missing = []
        for binary in self.required_binaries:
            if not shutil.which(binary):
                missing.append(binary)
        return missing
VolatilityPlugin, SleuthKitCarver, MemoryStringCarver, CacheQueryTool all implement Tool.
The ToolRegistry maps ActionType to Tool instances and validates inputs using the tool's ToolInput model.
REQ-MOD-002: Configuration-Driven Evidence Discovery
Current State: Hardcoded glob patterns in extractor.py.  Target State: Configurable discovery rules.
Specification:
config.py should define EVIDENCE_PATTERNS as a list of glob/regex rules.
Support user-defined overrides via evidence_manifest.json in EVIDENCE_DIR.
Example manifest:
JSON
{
  "memory_images": ["case_001.raw", "case_001.mem"],
  "disk_images": ["case_001.e01"],
  "bodyfile": "case_001_bodyfile.txt"
}
If a manifest is present, bypass auto-discovery and use the explicit list.
6. API & Interface Specifications
6.1 AgentCommand Schema (Pydantic v2)
Python
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator
import re

class ActionType(str, Enum):
    GET_EVIDENCE_CONTEXT = "get_evidence_context"
    QUERY_JSON_CACHE = "query_json_cache"
    EXTRACT_AND_CARVE_HIVE = "extract_and_carve_hive"
    CARVE_MEMORY_STRINGS = "carve_memory_strings"
    REQUEST_HUMAN_REVIEW = "request_human_review"

class AgentCommand(BaseModel):
    reasoning: str = Field(
        ..., 
        max_length=300, 
        description="State current PID, current step, and logic."
    )
    extracted_target: str = Field(
        default="NONE",
        pattern=r"^(NONE|[0-9]+)$",
        description="PID number or NONE."
    )
    action: ActionType = Field(
        ..., 
        description="The action to execute. Must be from the allowed enum."
    )
    kwargs: dict = Field(
        default_factory=dict,
        description="Action-specific parameters."
    )

    @field_validator("kwargs")
    @classmethod
    def validate_kwargs(cls, v: dict, info) -> dict:
        action = info.data.get("action")
        if action == ActionType.QUERY_JSON_CACHE:
            if "cache_name" not in v or not isinstance(v["cache_name"], str):
                raise ValueError("query_json_cache requires string cache_name")
            allowed = {"pstree", "cmdline", "registry_map", "netscan", "malfind"}
            if v["cache_name"] not in allowed:
                raise ValueError(f"cache_name must be one of {allowed}")

        elif action == ActionType.EXTRACT_AND_CARVE_HIVE:
            inode = v.get("inode", "")
            if not isinstance(inode, str) or not re.match(r"^[\d\-]+$", inode):
                raise ValueError("inode must be a valid inode string (digits and hyphens)")
            if "disk_image_path" in v:
                p = v["disk_image_path"]
                if not isinstance(p, str) or ".." in p or any(c in p for c in ";|&$`"):
                    raise ValueError("disk_image_path contains unsafe characters")

        elif action == ActionType.CARVE_MEMORY_STRINGS:
            pat = v.get("regex_pattern", "")
            if not isinstance(pat, str) or len(pat) > 200:
                raise ValueError("regex_pattern must be a string under 200 chars")
            try:
                re.compile(pat)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")

        elif action == ActionType.REQUEST_HUMAN_REVIEW:
            if "keyword" not in v or not isinstance(v["keyword"], str):
                raise ValueError("request_human_review requires string keyword")

        return v
6.2 State Machine Transition Table
Table
Current State	Trigger / Condition	Next State	Expected Action
S0_INIT	User types "investigate"	S1_ACQUIRE_CONTEXT	get_evidence_context
S1_ACQUIRE_CONTEXT	Context received	S2_ENUMERATE_PIDS	query_json_cache (malfind)
S2_ENUMERATE_PIDS	PIDs list received	S3_PID_PSTREE	query_json_cache (pstree)
S3_PID_PSTREE	pstree received	S4_PID_CMDLINE	query_json_cache (cmdline)
S4_PID_CMDLINE	cmdline received	S5_PID_REGISTRY	query_json_cache (registry_map)
S5_PID_REGISTRY	registry_map received	S6_PID_HIVE_CARVE	extract_and_carve_hive
S6_PID_HIVE_CARVE	hive result received	S7_PID_NETSCAN	query_json_cache (netscan)
S7_PID_NETSCAN	netscan received	S8_PID_MEMORY_CARVE	carve_memory_strings
S8_PID_MEMORY_CARVE	memory strings received	S9_PID_EVALUATE	(LLM evaluates Null Hypothesis)
S9_PID_EVALUATE	More PIDs remain	S3_PID_PSTREE	(next PID)
S9_PID_EVALUATE	No more PIDs	S10_COMPLETE	request_human_review
*_RECOVERY	Validation failure	(retry previous state)	(corrective prompt)
*_RECOVERY	Max retries exceeded	S10_COMPLETE	request_human_review (error)
6.3 Tool Output Contract
Every tool must return a ToolOutput with the following structure:
JSON
{
  "success": true,
  "data": { ... },
  "error_message": null,
  "execution_time_ms": 15420,
  "metadata": {
    "tool_version": "volatility3 2.5.0",
    "cache_hit": false,
    "output_truncated": false
  }
}
success: Boolean indicating whether the tool completed its primary objective.
data: The actual payload (can be any JSON-serializable structure).
error_message: Human-readable error if success is false.
execution_time_ms: Wall-clock time for the tool invocation.
metadata: Tool-specific metadata for observability.
7. Implementation Roadmap
Phase 1: Security Foundation & Input Hardening (Weeks 1–2)
Objective: Close all P0 security vulnerabilities before any other work proceeds.
Deliverables:
[ ] Implement SafeSubprocessRunner with shell=False, path validation, and sandbox enforcement.
[ ] Implement AgentCommand Pydantic schema with strict kwargs validation.
[ ] Refactor extract_and_carve_hive, carve_memory_strings, generate_bodyfile, and run_plugin to use SafeSubprocessRunner.
[ ] Add input validation for inode, pid, regex_pattern, and all paths.
[ ] Security audit: Run bandit and semgrep on the entire codebase. Zero high-severity findings allowed.
[ ] Update stress_test.py to attempt command injection and path traversal; verify they are rejected.
Definition of Done:
bandit reports zero B605 (shell=True) and B608 findings.
Fuzzing 100 random path strings results in 100 rejections for paths outside the sandbox.
Phase 2: Deterministic State Machine & LLM Gateway (Weeks 3–4)
Objective: Replace the prompt-based state machine with a code-based FSM and robust LLM I/O.
Deliverables:
[ ] Implement InvestigationStateMachine with explicit states, transitions, and max-iteration guards.
[ ] Refactor orchestrator.py main loop to use the FSM as the authority; LLM output is advisory.
[ ] Implement APIGovernor with token-bucket rate limiting and adaptive backoff.
[ ] Rewrite the system prompt to be schema-first, concise, and honest about probabilistic behavior.
[ ] Implement hallucination detection and corrective feedback loop.
[ ] Add RECOVERY state handling for JSON parse failures and validation errors.
Definition of Done:
The agent completes the full heuristic loop on mock data even when the LLM hallucinates a wrong action (FSM overrides and recovers).
Mock LLM returning invalid JSON 3 times in a row triggers RECOVERY and then COMPLETE.
Phase 3: Performance, Async & Data Layer (Weeks 5–6)
Objective: Eliminate blocking I/O and memory pressure; implement production-grade caching.
Deliverables:
[ ] Convert mcp_server.py tool functions to async using asyncio.create_subprocess_exec.
[ ] Implement streaming string carving with line-by-line generators and Python-native filtering.
[ ] Implement SQLiteCache with WAL mode, indexing, and TTL support.
[ ] Migrate pstree, cmdline, netscan, malfind, and registry_map caches to SQLite.
[ ] Implement ProcessPoolExecutor for CPU-bound carving tasks.
[ ] Implement extraction DAG in extractor.py for parallel pre-warming.
Definition of Done:
Agent can process a 32GB mock memory image without exceeding 2GB RAM usage.
Cache query latency for netscan with 100,000 rows is under 50ms.
asyncio.gather() successfully runs pstree and cmdline in parallel.
Phase 4: Resilience, Observability & Testing (Weeks 7–8)
Objective: Harden against edge cases, add comprehensive testing, and implement audit logging.
Deliverables:
[ ] Implement structured exception hierarchy (DFIRError subclasses).
[ ] Implement fallback chains for all tools with explicit logging.
[ ] Implement atomic_write and filelock for all file operations.
[ ] Implement immutable thought ledger with hash chaining.
[ ] Implement JSON-structured logging and Prometheus metrics.
[ ] Write comprehensive unit tests for SafeSubprocessRunner, InvestigationStateMachine, AgentCommand validation, and all tool wrappers.
[ ] Write integration tests with mocked vol, icat, strings, and mmls binaries.
[ ] Write property-based tests (Hypothesis) for input validation functions.
[ ] Remove getpass.getpass from generate_mitre_report; replace with HSM/key-file based signing or optional interactive mode.
Definition of Done:
90% unit test coverage.
All file operations use atomic writes.
Thought ledger passes verify_ledger() after 1000 simulated steps.
Agent gracefully handles missing vol binary by disabling memory mode and continuing.
8. Risk Assessment & Mitigation
Table
Risk	Likelihood	Impact	Mitigation
LLM API changes or deprecation	Medium	High	Abstract LLM calls behind LLMGateway interface. Support fallback to OpenAI/Anthropic with minimal code changes.
Volatility 3 plugin output format changes	Medium	High	Version-pin Volatility in requirements. Add output schema adapters that normalize different versions to a common internal format.
Evidence corruption causing infinite tool hangs	High	High	Hard timeouts on all subprocesses. Health check validates evidence file headers before full processing.
Concurrent agent instances corrupting cache	Medium	High	SQLite WAL mode + file locking. Atomic writes. Cache entries are immutable once written.
Adversarial evidence designed to exploit parser	Low	Critical	Input validation on all paths. shell=False. Fuzz testing of MBR/GPT parser with malformed sectors.
Analyst workstation resource exhaustion	High	Medium	Memory limits on subprocess output. Streaming processing. Configurable max workers.
LLM hallucination causing investigation loop	Medium	Medium	FSM enforcement. Max iteration guards. Divergence detection.
9. Success Criteria & KPIs
9.1 Security KPIs
Zero shell=True usages in production code.
100% of LLM outputs pass Pydantic schema validation before tool execution.
100% of file paths pass sandbox validation before reaching any subprocess.
9.2 Reliability KPIs
99.9% of investigations complete without crashing (measured over 1000 mock runs with injected faults).
100% of subprocess invocations have enforced timeouts.
Zero silent exception swallows (all exceptions logged and categorized).
9.3 Performance KPIs
< 2GB peak RAM usage during a 32GB memory image investigation.
< 50ms cache query latency for indexed lookups (p99).
< 5s API governor overhead per 100 LLM calls (adaptive vs. fixed sleep).
9.4 Observability KPIs
100% of state transitions logged with structured JSON.
100% of thought ledger entries pass hash-chain verification.
< 1s latency for Prometheus metrics scrape endpoint.
10. Appendices
Appendix A: Prompt Engineering Specification (v0.1.5)
Text
You are the Universal Forensic Engine (UFE), an AI advisor for Windows DFIR investigations.
You analyze memory and disk images to identify compromised processes.

OUTPUT RULES:
1. Output ONLY a single JSON object. No markdown fences, no explanatory text outside JSON.
2. Do not invent actions. Use only the actions listed below.
3. Keep reasoning under 200 characters.

JSON SCHEMA:
{
  "reasoning": "string (max 200). State current PID and step.",
  "extracted_target": "string: PID number or 'NONE'",
  "action": "enum: get_evidence_context | query_json_cache | extract_and_carve_hive | carve_memory_strings | request_human_review",
  "kwargs": "object. Parameters for the chosen action."
}

ACTIONS:
- get_evidence_context: {}
- query_json_cache: {"cache_name": "pstree|cmdline|registry_map|netscan|malfind", "keyword": "string"}
- extract_and_carve_hive: {"inode": "string", "disk_image_path": "string (optional)"}
- carve_memory_strings: {"regex_pattern": "NETWORK or custom regex", "memory_image_path": "string (optional)"}
- request_human_review: {"keyword": "summary string"}

INVESTIGATION PROTOCOL:
1. Call get_evidence_context.
2. Query malfind with keyword 'PAGE_EXECUTE_READWRITE' to get anomalous PIDs.
3. For EACH PID in order:
   A. Query pstree for the PID.
   B. Query cmdline for the PID.
   C. Query registry_map for the PID (or 'SYSTEM'), then extract_and_carve_hive.
   D. Query netscan for the PID.
   E. Call carve_memory_strings with regex_pattern "NETWORK".
   F. If hive is clean AND network indicators are benign, declare Null Hypothesis and proceed to next PID.
4. After all PIDs, call request_human_review.

EXAMPLE 1:
Input: [SYSTEM DATA: get_evidence_context] {"MODE": "HYBRID"}
Output: {"reasoning":"Context acquired. Mode HYBRID.","extracted_target":"NONE","action":"query_json_cache","kwargs":{"cache_name":"malfind","keyword":"PAGE_EXECUTE_READWRITE"}}

EXAMPLE 2:
Input: [SYSTEM DATA: query_json_cache] PIDs: 1234, 5678
Output: {"reasoning":"Anomalous PIDs found. Starting with 1234.","extracted_target":"1234","action":"query_json_cache","kwargs":{"cache_name":"pstree","keyword":"1234"}}
Key Changes from v0.1.4:
Removed false "deterministic state machine" claim.
Added strict JSON Schema block.
Added few-shot examples.
Shortened from ~60 lines to ~30 lines.
Explicit action enum prevents hallucination of read_dfir_playbook.
Appendix B: Threat Model
Threat Actor: Sophisticated adversary with access to the evidence image before the DFIR agent processes it.
Attack Vectors:
Evidence Poisoning: Adversary embeds strings in memory that look like valid paths or commands to influence LLM reasoning.
Mitigation: LLM does not execute paths directly. All paths are validated against the sandbox.
Cache Poisoning: Adversary modifies malfind.json or netscan.json in the cache directory to inject fake PIDs or C2 IPs.
Mitigation: Cache files are stored in a directory with restricted permissions. Cache integrity is verified via evidence file hash. SQLite WAL mode prevents corruption.
Prompt Injection via Evidence: Adversary places strings like ignore previous instructions in memory.
Mitigation: System prompt is fixed and high-priority. User/evidence data is clearly delimited with [SYSTEM DATA: ...] markers. However, this is an active research area; defense in depth is critical.
Resource Exhaustion: Adversary provides a 1TB memory image or a zip bomb.
Mitigation: File size limits enforced before processing. Streaming pipelines with line caps. Timeouts on all operations.
Appendix C: Migration Plan from v0.1.4
Branch Strategy: Create v0.1.5-refactor branch. Do not attempt incremental refactoring on main.
File Breakdown:
agent.py → llm_gateway.py + prompts.py
mcp_server.py → tools/ directory with volatility_tool.py, sleuthkit_tool.py, carver_tool.py, cache_tool.py
extractor.py → evidence_discovery.py + cache_builder.py
orchestrator.py → orchestrator.py (slimmed) + state_machine.py + telemetry.py
config.py → settings.py (Pydantic-Settings based, with env var validation)
Backward Compatibility:
v0.2.0 can read v0.1.4 JSON cache files for migration, but writes only in the new SQLite format.
ioc_store.json is migrated to the new SQLite schema on first run.
Testing:
v0.1.4 stress_test.py is preserved as a regression test until v0.1.5 equivalents pass.
All v0.1.4 mock data is reused for v0.1.5 integration tests.
11. Document Sign-off
Table
Role	Name	Date	Status
Principal Engineer	(Author)	2026-06-02	✅ Approved
Security Architect	(Review)	TBD	⏳ Pending
Engineering Lead	(Review)	TBD	⏳ Pending
DFIR Analyst (User)	(Review)	TBD	⏳ Pending
