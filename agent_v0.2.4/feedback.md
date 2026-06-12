Gemini

The architectural flaw in "Project Find Evil" is a classic scaling bottleneck: tight coupling to a specific telemetry type. By anchoring the orchestration state machine to Process IDs, the system is fundamentally a memory-analyzer rather than a universal DFIR agent.

To achieve commercial viability and true autonomy, the architecture must transition from a **PID-Centric model** to an **Entity-Centric model**. An "Entity" is an abstraction that can represent a PID, a file path, a registry key, or a network socket.

Here is the strategic refactor to cure "Disk-Blindness" and resolve the Volatility parsing errors.

---

### 1. Refactoring the Heuristic Engine (`sieve.py`)

`sieve.py` must stop returning lists of PIDs and start returning lists of `SuspectEntity` dictionaries. This decoupling allows the LLM agent to evaluate the *behavior* or *location* of the entity, regardless of whether it is currently executing in memory.

**Conceptual Data Structure:**

```python
# sieve.py abstract data model
suspect_entity = {
    "entity_type": "REGISTRY_KEY", # or "PID", "FILE_PATH", "SERVICE"
    "identifier": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MaliciousUpdater",
    "threat_score": 85,
    "evidence_links": ["registry_map.json", "bodyfile.txt"],
    "context": {
        "value": "C:\\Temp\\svchost.exe",
        "last_modified": "2026-06-04 14:00:00"
    }
}

```

**Scoring Logic:** You implement separate scoring modules.

* `score_memory_entities()` digests the Volatility caches.
* `score_disk_entities()` digests the bodyfile (looking for execution in `Temp`, `AppData`, or timeline anomalies) and registry maps.
* `sieve.py` merges these lists, ranks them globally by `threat_score`, and hands the top *N* entities to the LLM.

### 2. Upgrading the State Machine (`orchestrator.py`)

The orchestrator needs a routing mechanism at initialization to determine the available evidence and spin up the corresponding pipelines concurrently or sequentially.

**State Flow:**
`INIT` $\rightarrow$ `EVIDENCE_DISCOVERY` $\rightarrow$ `ROUTER` $\rightarrow$ (`MEMORY_PIPELINE` AND/OR `DISK_PIPELINE`) $\rightarrow$ `SIEVE_AGGREGATION` $\rightarrow$ `LLM_EVALUATION`

**Dynamic Switch Logic:**

```python
# orchestrator.py
def route_investigation(evidence_inventory):
    pipelines_to_run = []
    
    if evidence_inventory.get("memory_caches_populated"):
        pipelines_to_run.append(run_memory_pipeline)
    
    if evidence_inventory.get("registry_maps_populated") or evidence_inventory.get("bodyfile_present"):
        pipelines_to_run.append(run_disk_pipeline)
        
    if not pipelines_to_run:
        print("[-] FATAL: No valid telemetry discovered. Terminating.")
        return []

    global_entities = []
    for pipeline in pipelines_to_run:
        global_entities.extend(pipeline())
        
    return global_entities

```

### 3. Practical First Step: The Autoruns Trigger

To give the LLM an immediate entry point when dealing with a dead disk, querying persistence mechanisms (Autoruns) is the highest-fidelity starting point. Assuming your `registry_map.json` tracks the physical location of the hives, `sieve.py` can wrap a lightweight extraction script to pull out the `Run` keys.

*Note: Since pure Python struggles to parse raw Windows Registry hive binaries without heavy external libraries, the merchant approach is to use a subprocess wrapper around a native tool (like `rip.pl` / RegRipper or SleuthKit's `icat`) to dump the specific key, or utilize a lightweight zero-dependency parser if you have written one.*

```python
# disk_trigger.py (called by sieve.py)
import json
import re

def extract_autoruns(registry_map_path, hive_parser_wrapper):
    """
    Parses known persistence locations from mapped dead-disk hives to generate initial Suspect Entities.
    """
    entities = []
    with open(registry_map_path, 'r') as f:
        reg_map = json.load(f)
        
    software_hive = reg_map.get("SOFTWARE")
    
    if software_hive:
        print("[*] Extracting HKLM\\Software\\...\\Run keys...")
        # Abstracted call to your hive parsing utility
        run_keys = hive_parser_wrapper(software_hive, "Microsoft\\Windows\\CurrentVersion\\Run")
        
        for key_name, file_path in run_keys.items():
            # Heuristic check: Is the startup item running from a suspicious directory?
            score = 0
            if re.search(r'(?i)(\\Temp\\|\\AppData\\Local\\|C:\\Users\\Public\\)', file_path):
                score += 60
                
            if score > 0:
                entities.append({
                    "entity_type": "REGISTRY_AUTORUN",
                    "identifier": f"HKLM Run: {key_name}",
                    "threat_score": score,
                    "evidence_links": [software_hive],
                    "context": {"target_binary": file_path}
                })
                
    return entities

```

### 4. Resolving Volatility Truncation False Positives

The `EPROCESS` block in Windows memory naturally truncates the `ImageFileName` field. Volatility 2 truncates at 14 characters, and Volatility 3 at 15. If a legitimate process has a long name (e.g., `MicrosoftEdgeCP.exe`), Volatility extracts it as `MicrosoftEdgeC`, which `sieve.py` flags as an anomaly because it lacks an extension or looks malformed.

**The Fix:**
You must implement a length-check heuristic and cross-reference it with the `cmdline` cache, which contains the full, untruncated path.

```python
# sieve.py (Memory Heuristics snippet)

def score_process_name(process_name, pid, cmdline_cache):
    score = 0
    
    # Check for exact 14/15 char length, indicating natural EPROCESS truncation
    if len(process_name) in [14, 15] and not process_name.endswith('.exe'):
        # Do NOT flag immediately. Cross-reference cmdline cache to verify the real name.
        full_cmdline = cmdline_cache.get(str(pid), "")
        
        if process_name.lower() in full_cmdline.lower():
            # It's a truncated legitimate process. Nullify the anomaly score.
            print(f"[~] Info: PID {pid} name '{process_name}' is a truncated artifact. Validated against cmdline.")
            return 0
        else:
            # If it's 14/15 chars but doesn't match its own cmdline context, that is highly suspicious (Process Hollowing/Spoofing).
            score += 75
            
    # Standard anomaly checks (e.g., random characters, single letter names)
    elif len(process_name) < 4 or process_name.count('.') > 1:
        score += 40
        
    return score

```



Copilot

### Summary
Below I outline an architectural refactor and provide concrete code changes so your DFIR agent can start investigations from **disk-only**, **memory-only**, or **hybrid** evidence. The approach:

- Generalize the heuristic engine to score **entities** (processes, registry keys, file paths, Amcache/Prefetch entries) instead of only PIDs.
- Make `sieve.py` return a unified `suspect_entities` list with **type**, **score**, and **evidence**.
- Make `orchestrator.py` detect available evidence (non-empty memory caches vs disk artifacts) and select a **state machine** (memory-first, disk-first, hybrid).
- Provide a practical first-step disk trigger: **extract Autoruns-like entries from `registry_map.json` and bodyfile** and score them as suspect entities.
- Add a robust fix for **truncated process names** to reduce false positives.

---

### Design changes and rationale
- **Entity model**: unify everything under an `Entity` dict:
  ```py
  {
    "id": "proc:1234" | "reg:HKLM\\...\\Run\\Bad",
    "type": "process" | "registry" | "file" | "amcache" | "prefetch",
    "label": "svchost.exe" | "HKLM\\...\\Run\\Bad",
    "attributes": {...},   # plugin outputs, file path, registry value, source_image
    "score": 0.0,
    "reasons": ["heuristic1", "heuristic2"]
  }
  ```
- **Scoring engine**: implement `score_entity(entity)` that dispatches to `score_process`, `score_registry`, `score_file`, etc. Each scorer returns `(score, reasons)`.
- **Thresholds**: keep a single threshold for "suspect" but allow per-type thresholds (e.g., registry entries may need lower threshold).
- **Evidence detection**: orchestrator checks for non-empty memory caches (e.g., `pslist.json` with entries) and disk artifacts (`registry_map_*.json`, `bodyfile_*.txt`, `amcache.json`) and chooses pipeline:
  - **Memory-first**: if memory caches present and non-empty.
  - **Disk-first**: if no memory caches but disk artifacts present.
  - **Hybrid**: both present — run memory scoring first, then expand with disk-based entities.
- **Workflow**:
  1. Orchestrator collects caches and artifact paths.
  2. Calls `sieve.score_all(caches, artifacts)` which returns `suspect_entities`.
  3. If `suspect_entities` non-empty, orchestrator seeds LLM agent with them; otherwise escalate to deeper disk hunts (e.g., full Autoruns, Amcache parsing).

---

### sieve.py adjustments
Replace PID-only logic with the following core functions and flow. This is a drop-in style patch — keep your existing helpers but replace the main scoring flow.

```python
# sieve.py (excerpt)
import json
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Any

# Config
SUSPECT_THRESHOLD = 0.7
REGISTRY_SUSPECT_THRESHOLD = 0.5

logging.basicConfig(level=logging.INFO)

def load_json_if_exists(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return data
    except Exception:
        logging.exception("Failed to load JSON %s", path)
        return None

def normalize_proc_name(name: str) -> str:
    # Trim whitespace, strip nulls, remove trailing ellipses used by some tools
    if not name:
        return ""
    name = name.strip()
    name = name.replace("\x00", "")
    # remove common truncation markers
    name = name.rstrip(".")
    # If name contains '...' or endswith truncated token, remove them
    name = name.replace("...", "")
    return name

def score_process(proc_entry: Dict) -> Tuple[float, List[str]]:
    """
    proc_entry expected keys: pid, name, cmdline, image_path, truncated_flag (optional)
    Return (score, reasons)
    """
    score = 0.0
    reasons = []
    name = normalize_proc_name(proc_entry.get("name", ""))
    cmdline = proc_entry.get("cmdline", "") or ""
    image_path = proc_entry.get("image_path", "") or ""

    # Heuristic: suspicious name patterns
    suspicious_names = ("svchost.exe", "rundll32.exe", "powershell.exe", "cmd.exe")
    if name.lower() in suspicious_names:
        score += 0.25
        reasons.append("suspicious_wellknown_name")

    # Heuristic: network connections
    if proc_entry.get("has_network", False):
        score += 0.25
        reasons.append("network_activity")

    # Heuristic: unusual parent or missing parent
    if proc_entry.get("parent_missing", False):
        score += 0.15
        reasons.append("parent_missing")

    # Heuristic: long/obfuscated cmdline
    if len(cmdline) > 200 or " -enc " in cmdline.lower():
        score += 0.2
        reasons.append("suspicious_cmdline")

    # Truncation handling: if name looks truncated, lower confidence and consult cmdline/image_path
    truncated = proc_entry.get("truncated", False)
    if truncated:
        # If cmdline or image_path corroborates maliciousness, keep score; otherwise reduce
        if any(tok in cmdline.lower() for tok in ("-enc", "Invoke-Expression", "IEX", "Base64")) or "temp" in image_path.lower():
            reasons.append("truncated_name_but_cmdline_correlates")
        else:
            score *= 0.5
            reasons.append("truncated_name_uncertain")

    # Cap score
    score = min(1.0, score)
    return score, reasons

def score_registry_autorun(reg_entry: Dict) -> Tuple[float, List[str]]:
    """
    reg_entry keys: hive, key_path, value_name, value_data, source_image
    """
    score = 0.0
    reasons = []
    val = reg_entry.get("value_name", "").lower()
    data = reg_entry.get("value_data", "").lower()
    key = reg_entry.get("key_path", "").lower()

    # Known autorun locations
    autorun_tokens = ("\\run\\", "\\runonce\\", "\\services\\", "winlogon", "userinit", "shell")
    if any(tok in key for tok in autorun_tokens):
        score += 0.4
        reasons.append("autorun_location")

    # Suspicious data: remote URLs, temp paths, odd exe names
    if data.startswith("http") or "temp" in data or data.endswith(".bat") or data.endswith(".vbs"):
        score += 0.35
        reasons.append("suspicious_value_data")

    # If value name is suspicious (e.g., random GUID)
    if len(val) > 20 and not any(c.isalpha() for c in val):
        score += 0.2
        reasons.append("random_value_name")

    score = min(1.0, score)
    return score, reasons

def score_file_path(file_entry: Dict) -> Tuple[float, List[str]]:
    """
    file_entry keys: path, size, mtime, source_image
    """
    score = 0.0
    reasons = []
    path = file_entry.get("path", "").lower()
    if "\\appdata\\roaming\\" in path or "\\temp\\" in path:
        score += 0.25
        reasons.append("user_temp_location")
    if path.endswith(".exe") and ("\\users\\" in path and "\\appdata\\" in path):
        score += 0.25
        reasons.append("exe_in_user_appdata")
    # suspicious filename tokens
    if any(tok in path for tok in ("\\autorun.inf", "\\runonce", "suspiciousname")):
        score += 0.3
        reasons.append("suspicious_filename_token")
    return min(1.0, score), reasons

def build_entity(entity_type: str, id_: str, label: str, attributes: Dict) -> Dict:
    return {
        "id": f"{entity_type}:{id_}",
        "type": entity_type,
        "label": label,
        "attributes": attributes,
        "score": 0.0,
        "reasons": []
    }

def score_all(memory_caches: Dict[str, Any], disk_artifacts: Dict[str, Any]) -> List[Dict]:
    """
    memory_caches: dict of plugin_name -> parsed JSON
    disk_artifacts: dict of artifact_name -> parsed JSON or paths (e.g., registry_map, bodyfile)
    Returns list of suspect entities (type, score, reasons)
    """
    entities = []

    # 1) Score processes from memory caches if present
    pslist = memory_caches.get("pslist") or []
    cmdline_map = {p.get("pid"): p.get("cmdline") for p in (memory_caches.get("cmdline") or [])}
    netscan = memory_caches.get("netscan") or []

    for p in pslist:
        pid = p.get("pid")
        proc = {
            "pid": pid,
            "name": p.get("name"),
            "cmdline": cmdline_map.get(pid, ""),
            "image_path": p.get("image"),
            "has_network": any(n.get("pid") == pid for n in netscan),
            "parent_missing": p.get("ppid") in (0, None),
            "truncated": p.get("name", "").endswith("...") or ("\x00" in (p.get("name") or ""))
        }
        ent = build_entity("process", str(pid), proc["name"], proc)
        score, reasons = score_process(proc)
        ent["score"] = score
        ent["reasons"] = reasons
        entities.append(ent)

    # 2) Score registry autoruns from disk artifacts
    registry_maps = disk_artifacts.get("registry_maps") or []
    for regmap in registry_maps:
        # regmap is expected to be dict hive-> {path, source_image}
        for hive, info in regmap.items():
            # naive extraction: if path contains Run keys, create an entity
            path = info.get("path", "")
            if not path:
                continue
            # create a registry autorun entity
            reg_entry = {
                "hive": hive,
                "key_path": path,
                "value_name": Path(path).name,
                "value_data": "",  # if you have parsed value data, include it
                "source_image": info.get("source_image")
            }
            ent = build_entity("registry", f"{hive}:{path}", f"{hive}::{path}", reg_entry)
            score, reasons = score_registry_autorun(reg_entry)
            ent["score"] = score
            ent["reasons"] = reasons
            entities.append(ent)

    # 3) Score suspicious file paths from bodyfile
    bodyfiles = disk_artifacts.get("bodyfiles") or []
    for bf in bodyfiles:
        # bf is expected to be a list of parsed bodyfile entries or raw text
        for line in bf:
            # parse bodyfile line if needed; assume dict with 'path'
            path = line.get("path") if isinstance(line, dict) else None
            if not path:
                continue
            file_entry = {"path": path, "size": line.get("size"), "source_image": line.get("source_image")}
            ent = build_entity("file", path, path, file_entry)
            score, reasons = score_file_path(file_entry)
            ent["score"] = score
            ent["reasons"] = reasons
            entities.append(ent)

    # 4) Filter suspects by thresholds (type-aware)
    suspects = []
    for e in entities:
        t = e["type"]
        if t == "registry" and e["score"] >= REGISTRY_SUSPECT_THRESHOLD:
            suspects.append(e)
        elif t == "process" and e["score"] >= SUSPECT_THRESHOLD:
            suspects.append(e)
        elif t == "file" and e["score"] >= SUSPECT_THRESHOLD:
            suspects.append(e)
        # else: keep for optional deeper analysis
    logging.info("Found %d suspect entities", len(suspects))
    return suspects
```

**Notes**
- `score_all` expects `memory_caches` and `disk_artifacts` to be preloaded by the orchestrator (see next section).
- Keep `SUSPECT_THRESHOLD` tunable. Registry entries often need a lower threshold because they are high-signal but low-volume.

---

### orchestrator.py adjustments
Make orchestrator detect evidence types and call `sieve.score_all` with appropriate inputs. The orchestrator should **not** exit immediately when memory caches are empty; instead it should run disk-based scoring.

```python
# orchestrator.py (excerpt)
import json
import logging
from pathlib import Path
from typing import Dict, Any, List
from sieve import score_all, load_json_if_exists

logging.basicConfig(level=logging.INFO)

MEMORY_CACHE_FILES = ["pslist.json", "cmdline.json", "netscan.json", "malfind.json"]
DISK_REGISTRY_GLOB = "registry_map_*.json"
DISK_BODYFILE_GLOB = "bodyfile_*.txt"

def collect_memory_caches(cache_dir: Path) -> Dict[str, Any]:
    caches = {}
    for fname in MEMORY_CACHE_FILES:
        p = cache_dir / fname
        data = load_json_if_exists(p)
        if data:
            caches[fname.replace(".json","")] = data
    return caches

def collect_disk_artifacts(cache_dir: Path) -> Dict[str, Any]:
    artifacts = {"registry_maps": [], "bodyfiles": []}
    # registry maps
    for p in cache_dir.glob("registry_map_*.json"):
        try:
            data = json.loads(p.read_text())
            artifacts["registry_maps"].append(data)
        except Exception:
            logging.exception("Failed to load registry map %s", p)
    # bodyfiles: parse into simple dicts (inode|path|md5|size|...)
    for p in cache_dir.glob("bodyfile_*.txt"):
        lines = []
        for l in p.read_text().splitlines():
            parts = l.split("|")
            if len(parts) >= 2:
                lines.append({"inode": parts[0], "path": parts[1], "size": parts[3] if len(parts)>3 else None, "source_image": p.name})
        artifacts["bodyfiles"].append(lines)
    return artifacts

def choose_pipeline(memory_caches: Dict[str, Any], disk_artifacts: Dict[str, Any]) -> str:
    has_memory = bool(memory_caches)
    has_disk = bool(disk_artifacts["registry_maps"] or disk_artifacts["bodyfiles"])
    if has_memory and has_disk:
        return "hybrid"
    if has_memory:
        return "memory-first"
    if has_disk:
        return "disk-first"
    return "none"

def orchestrate(cache_dir: Path):
    memory_caches = collect_memory_caches(cache_dir)
    disk_artifacts = collect_disk_artifacts(cache_dir)
    pipeline = choose_pipeline(memory_caches, disk_artifacts)
    logging.info("Selected pipeline: %s", pipeline)

    if pipeline == "none":
        logging.info("No evidence found. Exiting.")
        return

    # Always run sieve.score_all with whatever evidence is available
    suspects = score_all(memory_caches, disk_artifacts)

    if not suspects:
        # If no suspects from initial pass, escalate to deeper disk hunts
        if pipeline in ("disk-first", "hybrid"):
            logging.info("No suspects found in initial pass. Running deeper disk hunts.")
            # Example deeper hunt: parse Amcache, Prefetch, full Autoruns extraction
            # call functions to parse amcache.json, prefetch, etc., then re-run score_all
            # (implement parse_amcache(), parse_prefetch() as needed)
            # disk_artifacts.update(parse_amcache(cache_dir))
            # suspects = score_all(memory_caches, disk_artifacts)
        else:
            logging.info("No anomalies crossed the heuristic threshold. Investigation Complete.")
            return

    # If suspects found, hand to LLM agent
    if suspects:
        logging.info("Seeding LLM agent with %d suspects", len(suspects))
        # agent.evaluate(suspects)  # your existing agent call
```

**Notes**
- `orchestrate` always calls `score_all` even if memory caches are empty.
- If no suspects are found initially, orchestrator can escalate to deeper disk parsing (Amcache, Prefetch, full Autoruns) and re-run scoring.

---

### Practical first step disk trigger Autoruns parser
Add a small helper that parses `registry_map_*.json` and attempts to extract likely Autoruns entries. This is a pragmatic first-step disk-only trigger.

```python
# autoruns_parser.py (helper)
import json
from pathlib import Path
import logging

AUTORUN_KEY_TOKENS = ("\\run\\", "\\runonce\\", "winlogon", "userinit", "shell", "\\services\\", "image\\load")

def extract_autoruns_from_registry_map(regmap: dict) -> list:
    """
    regmap: dict loaded from registry_map_<safe>.json
    Returns list of dicts: {hive, key_path, value_name, value_data, source_image}
    """
    results = []
    for hive, info in regmap.items():
        path = info.get("path", "")
        if not path:
            continue
        key_lower = path.lower()
        if any(tok in key_lower for tok in AUTORUN_KEY_TOKENS):
            results.append({
                "hive": hive,
                "key_path": path,
                "value_name": Path(path).name,
                "value_data": info.get("value_data", ""),  # if available
                "source_image": info.get("source_image")
            })
    return results

# Example usage inside orchestrator before calling sieve:
# for regmap in disk_artifacts['registry_maps']:
#     autoruns = extract_autoruns_from_registry_map(regmap)
#     disk_artifacts.setdefault('autoruns', []).extend(autoruns)
```

**Why this helps**
- Autoruns entries are high-signal for persistence. Even a small number of suspicious autoruns can seed the LLM with a starting point for disk-only investigations.
- This is fast and low-cost: it only needs `registry_map.json` which you already produce.

---

### Fix for truncated process names false positives
Add a small normalization and corroboration step before treating a truncated name as high-confidence malicious:

- **Detect truncation**: name ends with `...`, contains `\x00`, or equals a fixed-length field (if Volatility reports fixed width).
- **Corroborate**: if truncated, require at least one corroborating signal (network socket, suspicious cmdline, parent missing, unusual image path) before keeping full score.
- **Score reduction**: if no corroboration, reduce process score (e.g., multiply by 0.5) and mark `reasons` with `"truncated_name_uncertain"`.

This logic is included in `score_process` above. Additionally, when building `proc_entry` from Volatility caches, set `truncated` flag:

```py
# when building proc_entry from pslist
name = p.get("name", "")
truncated = name.endswith("...") or ("\x00" in name) or len(name) >= 255
proc_entry["truncated"] = truncated
```

---

### Next steps and optional improvements
- **Add Amcache/Prefetch parsers** and feed their artifacts into `disk_artifacts` for richer disk scoring.
- **Manifest-driven classification**: if you can add a manifest mapping images to types (memory/disk), classification becomes deterministic.
- **LLM prompt design**: when seeding the LLM with disk-based suspects, include `type`, `score`, `reasons`, and `source_image` so the agent can request targeted follow-ups (e.g., "pull file from disk image", "carve file", "run YARA").
- **Feedback loop**: let the LLM mark entities as false positives; feed that back to adjust thresholds or add suppression rules.

---

If you want, I can:
- Provide a ready-to-drop-in `autoruns` extraction module that parses raw registry hive files (using `python-registry`) and returns value data for better scoring.
- Extend the `sieve` scoring rules with Amcache/Prefetch heuristics and example thresholds tuned for Windows 10/11.
- Produce a small test harness that simulates memory-only, disk-only, and hybrid evidence to validate the orchestrator state switching.



Deepseek

## Architectural Fix: Universal Investigation (Memory + Disk)

### 1. Overview of the Problem

The current system is “PID‑centric”: `sieve.py` scores only Volatility‑derived PIDs, and `orchestrator.py` exits if no suspect PIDs are found. When only disk evidence is present, the entire pipeline stalls. We need a **unified investigation model** that can start from:

- **Memory** → suspect processes (PIDs)  
- **Disk** → suspect persistence (registry autoruns), anomalous file paths, or forensic artefacts (Amcache, Prefetch)  
- **Hybrid** → both  

Additionally, truncated process names (e.g. `"someverylongpro...exe"`) should not automatically raise high‑confidence alerts, because they are often a Volatility artefact, not actual malice.

---

### 2. Core Design Decisions

#### A. Unified “Suspect Entity” abstraction

Replace the narrow PID focus with a common data structure:

```python
@dataclass
class SuspectEntity:
    type: str          # "process", "autorun", "file_path", "service", ...
    identifier: str    # e.g. PID, registry key path, file path
    score: float
    evidence: dict     # raw evidence that justifies the score
```

Heuristic scoring functions produce a `List[SuspectEntity]` from whatever data is available.

#### B. Source‑aware orchestration

The orchestrator first probes the cache directory to determine which evidence domains are present (memory caches, disk caches). It then calls the appropriate sieve entry points and passes the resulting entities to the LLM agent. The investigation loop is agnostic to the entity type – the LLM decides what next steps to take (e.g. “dump process memory” vs “extract registry value”).

#### C. Extract rich disk artefacts early

To give `sieve.py` material for scoring, we **extend `extractor.py`** so that when processing a disk image it:

- Extracts the SYSTEM, SOFTWARE, and NTUSER.DAT hives (using `icat` from The Sleuth Kit)  
- Runs lightweight autoruns extraction (e.g. via `python-registry` or `reglookup`)  
- Saves the autoruns list to `autoruns_<base>.json`  
- (Optionally) logs suspicious file paths from the bodyfile into a `file_anomalies_<base>.json`

Then `sieve.py` can simply load those pre‑computed JSON files alongside Volatility outputs.

---

### 3. Refactoring `sieve.py` – Modular Heuristics

#### A. New structure

```python
def run_sieve(evidence_dir: str) -> List[SuspectEntity]:
    suspects = []

    # 1. Memory heuristics (if vol caches exist)
    pids = load_all_volatility_caches(evidence_dir)   # returns dict[str, any]
    if pids:
        suspects.extend(score_processes(pids))

    # 2. Disk autorun heuristics
    autoruns = load_all_autoruns(evidence_dir)        # list of autorun entries
    suspects.extend(score_autoruns(autoruns))

    # 3. Disk file‑path heuristics (from bodyfile or MFT)
    files = load_all_file_anomalies(evidence_dir)     # list of file entries
    suspects.extend(score_file_paths(files))

    # Remove duplicates, combine evidence, return those above threshold
    return [e for e in suspects if e.score > THRESHOLD]
```

Each scoring function is responsible for transforming raw data into entities with scores.

#### B. Example: autoruns scoring

```python
def score_autoruns(autoruns: list) -> List[SuspectEntity]:
    suspects = []
    for entry in autoruns:
        score = 0.0
        reasons = []

        # 1. Suspicious locations
        if entry.get("path", "").startswith("\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"):
            # common, not inherently suspicious
            score += 0.1
        else:
            score += 0.2   # unusual location

        # 2. Binary in temp / user writable folder
        cmd = entry.get("command", "")
        if any(x in cmd.lower() for x in ["temp", "tmp", "appdata\\roaming", "users\\public"]):
            score += 0.5
            reasons.append("binary in writable folder")

        # 3. Suspicious file names
        if re.search(r"(\.tmp|\.vbs|\.ps1|\.bat)\s", cmd, re.I):
            score += 0.6
            reasons.append("script in autoruns")

        # 4. Empty or missing binary
        if not cmd.strip():
            score += 0.7
            reasons.append("empty command")

        if score > 0.0:
            suspects.append(SuspectEntity(
                type="autorun",
                identifier=f"{entry.get('hive')}\\{entry.get('key')}\\{entry.get('value')}",
                score=score,
                evidence={"command": cmd, "reasons": reasons}
            ))
    return suspects
```

#### C. Handling truncated process names (false‑positive fix)

In `score_processes()`, before applying heuristics, inspect the process name:

```python
def is_truncated_artifact(proc: dict) -> bool:
    name = proc.get("ImageFileName", "")
    cmd  = proc.get("CommandLine", "")
    # Volatility often truncates at 15 chars + "…" or "~"
    if name.endswith("…") or name.endswith("~"):
        return True
    # Another heuristic: name is exactly 15 chars (FAT‑8.3) and cmd does not match
    if len(name) == 15 and cmd and name not in cmd:
        return True
    # Check if the name is just a prefix of the full command line
    # If the command line starts with a different executable, likely truncation
    if cmd and not cmd.startswith(name.rstrip("…").rstrip("~")):
        return True
    return False
```

Then in the scoring loop:

```python
    if is_truncated_artifact(proc):
        # Still record, but treat as low confidence
        score += 0.2   # mild indicator; requires further verification
        proc["truncation_warning"] = True
    else:
        # normal heuristic …
```

The LLM agent can be instructed to verify such processes by looking at the full filesystem path in disk evidence (if available) before calling it malicious.

---

### 4. Refactoring `orchestrator.py` – Dynamic State Machine

#### A. Determine available evidence

```python
def determine_evidence_mode(cache_dir: str) -> str:
    has_memory = any(f.startswith("vol_") and f.endswith(".json") for f in os.listdir(cache_dir))
    has_disk   = any(f.startswith("autoruns_") or f.startswith("bodyfile_") for f in os.listdir(cache_dir))
    if has_memory and has_disk:
        return "hybrid"
    elif has_memory:
        return "memory"
    elif has_disk:
        return "disk"
    return "none"
```

#### B. New investigation loop

```python
def investigate(evidence_dir: str):
    mode = determine_evidence_mode(CACHE_DIR)
    if mode == "none":
        log.error("No evidence caches found.")
        return

    # Generate suspect entities
    suspects = run_sieve(evidence_dir)   # calls the universal sieve
    if not suspects:
        log.info("No heuristic hits. Investigation complete.")
        return

    # Pass to LLM agent – one by one, or batched
    for ent in suspects:
        prompt = build_prompt_from_entity(ent, mode)
        response = llm_agent.investigate(prompt)
        # … carry out actions based on LLM’s requests …
```

The `build_prompt_from_entity()` function crafts a contextual prompt that tells the LLM what evidence is available (memory, disk, both) and what the suspect entity is. The LLM can then ask for:

- For a process PID: “run `malfind` on PID 1234”, “extract prefetch for that executable”  
- For a registry autorun: “retrieve the binary’s digital signature from disk”, “check timestamp of the autorun key”  
- For a file path: “extract strings from that file”, “verify whether it is known malware”

#### C. State machine adaptation

Instead of a linear PID‑only flow, implement a **task queue**:

- Initial state: `POPULATE_QUEUE` – sieve fills queue with suspect entities.  
- Then loop: `NEXT_ENTITY` → `LLM_INVESTIGATE` → `EXECUTE_ACTION` → back to `NEXT_ENTITY`.  
- The queue can be dynamically expanded if the LLM uncovers new suspects (e.g., a process loads a DLL that is also suspicious).

---

### 5. Practical First Step: Autoruns Extraction in `extractor.py`

Add this function to the disk‑processing pipeline:

```python
import subprocess, json

def extract_autoruns(disk_image: str, hives: dict, output_path: str):
    """
    Given registry_map.json {hive_name: inode_path}, 
    extract autorun keys from SYSTEM and SOFTWARE using reglookup.
    """
    autoruns = []
    for hive_name in ["SOFTWARE", "SYSTEM"]:
        if hive_name not in hives:
            continue
        inode_path = hives[hive_name]
        # Extract hive file from disk image using icat
        hive_file = f"/tmp/{hive_name.lower()}.hive"
        subprocess.run(["icat", disk_image, inode_path], stdout=open(hive_file, "wb"), check=True)

        # Use reglookup-recv to dump autorun paths (or python-registry)
        # Example with reglookup: reglookup-recv -t RUN* <hive_file>
        try:
            out = subprocess.check_output(
                ["reglookup-recv", "-t", "RUN*", hive_file], text=True
            )
            for line in out.strip().splitlines():
                parts = line.split(",")   # adjust based on format
                if len(parts) >= 4:
                    autoruns.append({
                        "hive": hive_name,
                        "key": parts[0],
                        "value": parts[1],
                        "type": parts[2],
                        "command": parts[3]
                    })
        except Exception:
            log.exception("reglookup failed, falling back to python-registry")
            # alternative: import Registry, parse the hive manually
            # …
        finally:
            os.remove(hive_file)

    with open(output_path, "w") as f:
        json.dump(autoruns, f, indent=2)
```

Call this from `process_disk()` after generating the registry map:

```python
def process_disk(disk_image: str):
    bodyfile_path = _cache_filename("bodyfile", disk_image, "txt")
    regmap_path   = _cache_filename("registry_map", disk_image, "json")
    autoruns_path = _cache_filename("autoruns", disk_image, "json")

    generate_bodyfile(disk_image, bodyfile_path)
    with open(regmap_path) as f:
        regmap = json.load(f)
    extract_autoruns(disk_image, regmap, autoruns_path)
    # … additional artefacts …
```

Now `sieve.py` can simply open `autoruns_<base>.json` and feed it to the new scoring logic.

---

### 6. Summary of Code Changes

| File | Change |
|------|--------|
| **extractor.py** | Add `extract_autoruns()`, call it in `process_disk()`. |
| **sieve.py** | Replace single PID‑list output with `List[SuspectEntity]`. Add `score_autoruns()`, `score_file_paths()`. Integrate truncation check in process scoring. |
| **orchestrator.py** | Replace rigid PID‑only start with `determine_evidence_mode()`, `run_sieve()`, and a task‑queue loop that handles any `SuspectEntity` type. |

This architecture makes the agent truly evidence‑agnostic, able to “find evil” whether it hides in memory, on disk, or both.



Kimi

Here is an architectural refactor that replaces the PID-centric pipeline with an **Entity-Centric Abstraction**. This allows `sieve.py` to score anything (processes, registry keys, file paths, services) and lets `orchestrator.py` dynamically select the correct investigation mode based on what evidence actually exists.

---

## 1. The Core Concept: Entity Abstraction

Stop thinking in PIDs. Think in **Entities**. A process is an entity. A `Run` key is an entity. A suspicious file path is an entity. The heuristic engine should score *entities*, not just processes.

### `entity_model.py` (New Module)

```python
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from enum import Enum, auto
from pathlib import Path

class EvidenceMode(Enum):
    MEMORY_ONLY = auto()
    DISK_ONLY = auto()
    HYBRID = auto()
    NONE = auto()

class EntityType(Enum):
    PROCESS = "process"
    NETWORK_CONN = "network_conn"
    DLL_INJECTION = "dll_injection"
    REGISTRY_KEY = "registry_key"
    AUTORUN_ENTRY = "autorun_entry"
    SERVICE_ENTRY = "service_entry"
    FILE_PATH = "file_path"
    ANOMALOUS_PATH = "anomalous_path"

@dataclass
class Entity:
    """
    Universal evidence container. Replaces the hardcoded 'suspect_pid' dict.
    """
    entity_id: str                      # e.g., "PROC_1234" or "REG_SOFTWARE_Run_0"
    entity_type: EntityType
    source_image: str                   # e.g., "cfreds_pc.dd" or "memdump.raw"
    name: str
    path: Optional[str] = None
    command_line: Optional[str] = None
    parent_id: Optional[str] = None     # For process trees
    score: float = 0.0
    indicators: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def add_indicator(self, description: str, weight: float):
        self.indicators.append(f"{description} (+{weight})")
        self.score += weight
```

---

## 2. Refactored `sieve.py` (Dual-Mode Heuristic Engine)

This version ingests **both** memory caches and disk caches, converts them into `Entity` objects, and applies mode-appropriate scoring. It also fixes the truncated process name false positive.

```python
#!/usr/bin/env python3
"""
Project Find Evil - Sieve (Entity-Centric Heuristic Engine)
Scores processes, registry keys, file paths, and autoruns uniformly.
"""

import json
import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from entity_model import Entity, EntityType, EvidenceMode

logger = logging.getLogger(__name__)

# --- Configuration ---
CACHE_DIR = Path("./cache")
SUSPICIOUS_PATHS = [
    r'\\Temp\\', r'\\tmp\\', r'\\AppData\\Local\\Temp',
    r'\\Users\\.*\\AppData\\Roaming\\',
    r'\\ProgramData\\',
    r'\\Windows\\Tasks\\', r'\\Windows\\System32\\Tasks\\'
]
SUSPICIOUS_EXTENSIONS = {'.ps1', '.vbs', '.js', '.bat', '.cmd', '.hta', '.dll', '.exe'}
KNOWN_GOOD_PROCESSES = {
    'svchost.exe', 'csrss.exe', 'smss.exe', 'services.exe', 'lsass.exe',
    'winlogon.exe', 'explorer.exe', 'SearchIndexer.exe', 'MsMpEng.exe',
    'taskhostw.exe', 'dllhost.exe', 'wmiprvse.exe', 'spoolsv.exe'
}

# --- Truncation Fix Lookup ---
# Windows EPROCESS.ImageFileName is 16 bytes (15 chars + null terminator).
# If a name is exactly 15 chars, it may be truncated. We map common truncations
# to their full names to prevent false positives.
TRUNCATION_MAP = {
    "SearchIndexer.ex": "SearchIndexer.exe",
    "MsMpEng.exe": "MsMpEng.exe",  # Actually fits, but good to be explicit
    "taskhostw.exe": "taskhostw.exe",
    # Add more as you discover them in your environment
}


def load_entities(mode: EvidenceMode) -> List[Entity]:
    """
    Master loader. Reads all cache files and converts them into Entity objects.
    """
    entities: List[Entity] = []
    
    if mode in (EvidenceMode.MEMORY_ONLY, EvidenceMode.HYBRID):
        entities.extend(_load_memory_entities())
    
    if mode in (EvidenceMode.DISK_ONLY, EvidenceMode.HYBRID):
        entities.extend(_load_disk_entities())
    
    return entities


def _load_memory_entities() -> List[Entity]:
    """Parse Volatility JSON caches into Process/Network entities."""
    entities = []
    
    vol_cache_files = list(CACHE_DIR.glob("volatility_*.json"))
    if not vol_cache_files:
        logger.warning("No Volatility cache files found.")
        return entities

    for cache_file in vol_cache_files:
        source_image = _extract_source_from_cache_name(cache_file.name)
        
        try:
            with open(cache_file) as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to parse {cache_file}: {e}")
            continue

        # Parse pslist/malfind/etc from the volatility structure
        plugins = data.get("plugins", {})
        
        # --- Process Entities from pslist ---
        pslist_data = plugins.get("windows.pslist.PsList", {})
        if isinstance(pslist_data, list):
            for proc in pslist_data:
                entity = _parse_process_to_entity(proc, source_image)
                entities.append(entity)
        
        # --- Network Entities from netscan ---
        netscan_data = plugins.get("windows.netscan.NetScan", {})
        if isinstance(netscan_data, list):
            for conn in netscan_data:
                # Simplified: create entities for suspicious connections
                pass  # Extend as needed
                
    return entities


def _parse_process_to_entity(proc: Dict[str, Any], source_image: str) -> Entity:
    """
    Convert a Volatility process dict into an Entity.
    FIXES THE TRUNCATION BUG by cross-referencing ImageFileName with full path.
    """
    pid = proc.get("PID", proc.get("pid", "0"))
    image_name = proc.get("ImageFileName", "UNKNOWN")
    cmdline = proc.get("CmdLine", "") or ""
    image_path = proc.get("ImagePathName", "") or ""
    
    # --- TRUNCATION FIX ---
    # If the name is exactly 15 chars, it is likely truncated by the Windows kernel.
    # We check the full path/cmdline to reconstruct the real name before scoring.
    resolved_name = image_name
    is_truncated = False
    
    if len(image_name) == 15:
        # Try to get the real name from the path
        full_name_from_path = Path(image_path).name if image_path else None
        full_name_from_cmd = Path(cmdline.split()[0]).name if cmdline else None
        
        candidate = full_name_from_path or full_name_from_cmd
        if candidate and len(candidate) > len(image_name) and candidate.startswith(image_name):
            resolved_name = candidate
            is_truncated = True
            logger.debug(f"Resolved truncated name '{image_name}' -> '{resolved_name}'")
        elif image_name in TRUNCATION_MAP:
            resolved_name = TRUNCATION_MAP[image_name]
            is_truncated = True
    
    entity = Entity(
        entity_id=f"PROC_{source_image}_{pid}",
        entity_type=EntityType.PROCESS,
        source_image=source_image,
        name=resolved_name,
        path=image_path,
        command_line=cmdline,
        raw_data=proc
    )
    
    # Mark truncation in raw data so downstream knows
    if is_truncated:
        entity.raw_data["__truncated_from"] = image_name
        entity.raw_data["__resolved_name"] = resolved_name
    
    return entity


def _load_disk_entities() -> List[Entity]:
    """
    Parse disk artifacts: bodyfile anomalies and registry_map autoruns.
    """
    entities = []
    
    # --- 1. Bodyfile Anomaly Detection (Works immediately with existing artifacts) ---
    bodyfiles = list(CACHE_DIR.glob("bodyfile_*.txt"))
    for bf in bodyfiles:
        source_image = _extract_source_from_cache_name(bf.name)
        entities.extend(_parse_bodyfile_anomalies(bf, source_image))
    
    # --- 2. Registry Map -> Autoruns (Requires hive extraction, see below) ---
    regmaps = list(CACHE_DIR.glob("registry_map_*.json"))
    for rm in regmaps:
        source_image = _extract_source_from_cache_name(rm.name)
        entities.extend(_parse_registry_autoruns(rm, source_image))
    
    return entities


def _parse_bodyfile_anomalies(bodyfile_path: Path, source_image: str) -> List[Entity]:
    """
    Scan the bodyfile for suspicious file paths that indicate persistence,
    staging, or living-off-the-land.
    """
    entities = []
    
    try:
        with open(bodyfile_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split('|')
                if len(parts) < 2:
                    continue
                
                filepath = parts[1]
                filename = Path(filepath).name
                ext = Path(filename).suffix.lower()
                
                score = 0.0
                indicators = []
                
                # Heuristic: Suspicious directory
                for pattern in SUSPICIOUS_PATHS:
                    if re.search(pattern, filepath, re.IGNORECASE):
                        score += 2.5
                        indicators.append(f"Suspicious path pattern: {pattern}")
                        break
                
                # Heuristic: Suspicious extension in system dirs
                if ext in SUSPICIOUS_EXTENSIONS and 'system32' in filepath.lower():
                    score += 3.0
                    indicators.append("Suspicious extension in System32")
                
                # Heuristic: Double extension (e.g., invoice.pdf.exe)
                if re.search(r'\.\w+\.(exe|dll|ps1|bat)$', filename, re.IGNORECASE):
                    score += 4.0
                    indicators.append("Double extension")
                
                # Heuristic: High entropy filename (random name = likely malware)
                if len(filename) > 12 and not re.search(r'[aeiou]', filename, re.IGNORECASE):
                    score += 1.5
                    indicators.append("High entropy filename")
                
                if score >= 3.0:
                    entity = Entity(
                        entity_id=f"FILE_{source_image}_{line_num}",
                        entity_type=EntityType.ANOMALOUS_PATH,
                        source_image=source_image,
                        name=filename,
                        path=filepath,
                        score=score,
                        indicators=indicators
                    )
                    entities.append(entity)
                    
    except Exception as e:
        logger.error(f"Failed to parse bodyfile {bodyfile_path}: {e}")
    
    return entities


def _parse_registry_autoruns(registry_map_path: Path, source_image: str) -> List[Entity]:
    """
    PRACTICAL FIRST STEP: Read registry_map.json and parse the actual hive files
    to extract Autoruns. This requires the hive files to be extracted from the
    disk image to a readable path (e.g., using fls/icat or bulk_extractor).
    
    NOTE: If hives are not yet extracted, this returns empty and falls back to
    bodyfile anomalies. See the extraction helper below.
    """
    entities = []
    
    try:
        with open(registry_map_path) as f:
            regmap = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Failed to load registry map {registry_map_path}: {e}")
        return entities
    
    # Attempt to locate extracted hive files
    # In a real pipeline, you would have extracted these hives to CACHE_DIR/hives/
    hive_dir = CACHE_DIR / "hives" / source_image
    software_hive = None
    system_hive = None
    
    for entry in regmap.get("SOFTWARE", []):
        if "SOFTWARE" in entry.get("path", "").upper():
            # Assume the hive was extracted to cache/hives/<source>/SOFTWARE
            potential = hive_dir / "SOFTWARE"
            if potential.exists():
                software_hive = str(potential)
                break
    
    for entry in regmap.get("SYSTEM", []):
        if "SYSTEM" in entry.get("path", "").upper():
            potential = hive_dir / "SYSTEM"
            if potential.exists():
                system_hive = str(potential)
                break
    
    if not software_hive and not system_hive:
        logger.info(f"No extracted hives found for {source_image}. Skipping registry autorun parse.")
        return entities
    
    # --- Parse SOFTWARE hive for Run/RunOnce keys ---
    # This requires 'regipy' or 'python-registry'. Install: pip install regipy
    try:
        from regipy import RegistryHive
        from regipy.structs import VALUE_TYPES
        
        if software_hive:
            hive = RegistryHive(software_hive)
            
            autorun_paths = [
                r"Microsoft\Windows\CurrentVersion\Run",
                r"Microsoft\Windows\CurrentVersion\RunOnce",
                r"Microsoft\Windows\CurrentVersion\RunOnceEx",
                r"WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
            ]
            
            for path in autorun_paths:
                try:
                    subkey = hive.get_key(path)
                    if not subkey:
                        continue
                    
                    for value in subkey.iter_values():
                        name = value.name
                        data = value.value
                        
                        score = 0.0
                        indicators = []
                        
                        # Heuristic: Suspicious path in autorun value
                        if isinstance(data, str):
                            if any(re.search(p, data, re.IGNORECASE) for p in SUSPICIOUS_PATHS):
                                score += 4.0
                                indicators.append("Autorun pointing to suspicious path")
                            
                            if re.search(r'\\Temp\\.*\.(exe|dll|ps1|bat)', data, re.IGNORECASE):
                                score += 5.0
                                indicators.append("Autorun in Temp with executable")
                            
                            if 'powershell' in data.lower() or 'cmd.exe' in data.lower() or 'cscript' in data.lower():
                                score += 2.0
                                indicators.append("Autorun using script host")
                        
                        if score > 0:
                            entity = Entity(
                                entity_id=f"REG_{source_image}_{path.replace('\\', '_')}_{name}",
                                entity_type=EntityType.AUTORUN_ENTRY,
                                source_image=source_image,
                                name=name,
                                command_line=str(data) if isinstance(data, str) else None,
                                path=f"SOFTWARE\\{path}",
                                score=score,
                                indicators=indicators,
                                raw_data={"value_type": value.value_type}
                            )
                            entities.append(entity)
                            
                except Exception as e:
                    logger.debug(f"Could not parse registry path {path}: {e}")
                    
    except ImportError:
        logger.warning("regipy not installed. Registry parsing disabled. Install: pip install regipy")
    except Exception as e:
        logger.error(f"Registry parsing failed: {e}")
    
    return entities


def _extract_source_from_cache_name(cache_name: str) -> str:
    """Extract source image name from cache filename like 'bodyfile_cfreds_pc.txt'"""
    # Remove prefix and suffix
    name = cache_name
    for prefix in ['bodyfile_', 'registry_map_', 'volatility_']:
        if name.startswith(prefix):
            name = name[len(prefix):]
    for suffix in ['.txt', '.json']:
        if name.endswith(suffix):
            name = name[:-len(suffix)]
    return name


# --- Heuristic Scoring Engine ---

def score_entities(entities: List[Entity]) -> List[Entity]:
    """
    Apply heuristics to all entities regardless of type.
    Returns only entities that cross the threshold.
    """
    threshold = 3.0
    
    for entity in entities:
        if entity.entity_type == EntityType.PROCESS:
            _score_process(entity)
        elif entity.entity_type == EntityType.AUTORUN_ENTRY:
            _score_autorun(entity)
        elif entity.entity_type == EntityType.ANOMALOUS_PATH:
            _score_anomalous_path(entity)
        # Add more dispatchers as needed
    
    # Sort by score descending
    scored = [e for e in entities if e.score >= threshold]
    scored.sort(key=lambda x: x.score, reverse=True)
    return scored


def _score_process(entity: Entity):
    """Memory-based process scoring. FIXED for truncation false positives."""
    name = entity.name.lower()
    cmdline = (entity.command_line or "").lower()
    path = (entity.path or "").lower()
    
    # --- FIX: If this was a resolved truncation, be less aggressive on name heuristics ---
    was_truncated = entity.raw_data.get("__truncated_from") is not None
    
    # Heuristic: Known good process
    if name in KNOWN_GOOD_PROCESSES:
        # If it was truncated but we resolved it to a known good process, 
        # do NOT penalize it. Give it a slight negative score (benign).
        if was_truncated:
            entity.score -= 2.0
            entity.indicators.append("Resolved truncated known-good process (benign)")
            return  # Skip further scoring for known-good resolved processes
        else:
            entity.score -= 1.0
    
    # Heuristic: Process running from Temp
    if r'\temp' in path or r'\tmp' in path:
        entity.add_indicator("Process executing from Temp", 4.0)
    
    # Heuristic: No command line (hollow process / injection candidate)
    if not entity.command_line or entity.command_line == "N/A":
        entity.add_indicator("Empty command line", 2.0)
    
    # Heuristic: Suspicious parent-child (e.g., Word spawning PowerShell)
    # This requires pstree correlation, simplified here
    if 'winword.exe' in str(entity.parent_id).lower() and 'powershell' in name:
        entity.add_indicator("Office app spawning PowerShell", 5.0)


def _score_autorun(entity: Entity):
    """Disk-based autorun scoring."""
    # Most scoring already done during extraction. Add cross-references here.
    if entity.score >= 5.0:
        entity.indicators.append("HIGH-CONFIDENCE PERSISTENCE MECHANISM")


def _score_anomalous_path(entity: Entity):
    """Disk-based file path scoring."""
    # Scoring done during extraction. Add additional context here.
    pass


def get_suspect_entities(mode: EvidenceMode) -> List[Entity]:
    """
    Public API. Replaces the old get_suspect_pids().
    Returns a list of suspicious entities for the LLM agent to investigate.
    """
    logger.info(f"Loading entities for mode: {mode.name}")
    entities = load_entities(mode)
    
    if not entities:
        logger.warning("No entities loaded from evidence.")
        return []
    
    scored = score_entities(entities)
    logger.info(f"Scored {len(scored)} entities above threshold.")
    return scored
```

---

## 3. Refactored `orchestrator.py` (Dynamic State Machine)

The orchestrator now detects what evidence exists, selects the appropriate mode, and routes to the correct entry-point handler.

```python
#!/usr/bin/env python3
"""
Project Find Evil - Orchestrator (Dynamic Mode State Machine)
Handles Memory-only, Disk-only, and Hybrid investigations.
"""

import logging
import sys
from pathlib import Path
from typing import List, Optional
from enum import Enum, auto

from entity_model import Entity, EntityType, EvidenceMode
from sieve import get_suspect_entities

logger = logging.getLogger(__name__)
CACHE_DIR = Path("./cache")

class InvestigationPhase(Enum):
    DISCOVERY = auto()
    HEURISTIC_SCORING = auto()
    ENTRY_POINT_SELECTION = auto()
    DEEP_INVESTIGATION = auto()
    CORRELATION = auto()        # Hybrid mode only
    REPORTING = auto()

class Orchestrator:
    def __init__(self):
        self.mode = self._detect_evidence_mode()
        self.phase = InvestigationPhase.DISCOVERY
        self.entities: List[Entity] = []
        self.investigated_ids: set = set()
        
    def _detect_evidence_mode(self) -> EvidenceMode:
        """
        Inspect the cache directory to determine what evidence we have.
        This is the single source of truth for pipeline routing.
        """
        has_memory = bool(list(CACHE_DIR.glob("volatility_*.json")))
        has_disk = bool(list(CACHE_DIR.glob("bodyfile_*.txt"))) or bool(list(CACHE_DIR.glob("registry_map_*.json")))
        
        if has_memory and has_disk:
            logger.info("HYBRID mode detected (memory + disk evidence)")
            return EvidenceMode.HYBRID
        elif has_memory:
            logger.info("MEMORY-ONLY mode detected")
            return EvidenceMode.MEMORY_ONLY
        elif has_disk:
            logger.info("DISK-ONLY mode detected")
            return EvidenceMode.DISK_ONLY
        else:
            logger.error("NO evidence artifacts found in cache directory.")
            return EvidenceMode.NONE

    def _select_entry_points(self) -> List[Entity]:
        """
        Choose the initial investigation targets based on mode.
        - Memory/Hybrid: Start with suspect Processes.
        - Disk-only: Start with Autoruns and Anomalous Paths.
        """
        if self.mode == EvidenceMode.MEMORY_ONLY:
            # Classic PID-centric entry
            procs = [e for e in self.entities if e.entity_type == EntityType.PROCESS]
            logger.info(f"Memory entry: {len(procs)} suspect processes")
            return procs[:10]  # Top 10
            
        elif self.mode == EvidenceMode.DISK_ONLY:
            # NEW: Disk-based entry points
            # Priority 1: Autoruns (persistence is the smoking gun)
            autoruns = [e for e in self.entities if e.entity_type == EntityType.AUTORUN_ENTRY]
            # Priority 2: Anomalous file paths
            files = [e for e in self.entities if e.entity_type == EntityType.ANOMALOUS_PATH]
            
            combined = autoruns + files
            logger.info(f"Disk entry: {len(autoruns)} autoruns, {len(files)} anomalous paths")
            return combined[:15]
            
        elif self.mode == EvidenceMode.HYBRID:
            # Hybrid: Start with processes, but enrich with disk correlation
            procs = [e for e in self.entities if e.entity_type == EntityType.PROCESS]
            # Also include high-confidence disk artifacts for cross-correlation
            disk_high = [e for e in self.entities 
                        if e.entity_type in (EntityType.AUTORUN_ENTRY, EntityType.ANOMALOUS_PATH) 
                        and e.score >= 5.0]
            return procs[:8] + disk_high[:5]
            
        return []

    def _investigate_entity(self, entity: Entity):
        """
        Hand entity to the LLM agent for evaluation.
        This replaces the old investigate(pid) function.
        """
        if entity.entity_id in self.investigated_ids:
            return
        
        self.investigated_ids.add(entity.entity_id)
        
        # Build context-aware prompt based on entity type
        if entity.entity_type == EntityType.PROCESS:
            prompt = self._build_process_prompt(entity)
        elif entity.entity_type == EntityType.AUTORUN_ENTRY:
            prompt = self._build_autorun_prompt(entity)
        elif entity.entity_type == EntityType.ANOMALOUS_PATH:
            prompt = self._build_file_prompt(entity)
        else:
            prompt = f"Investigate this entity: {entity}"
        
        # --- LLM CALL PLACEHOLDER ---
        logger.info(f"[*] Investigating {entity.entity_id} (score: {entity.score:.1f})")
        logger.info(f"    Type: {entity.entity_type.value} | Name: {entity.name}")
        logger.info(f"    Indicators: {entity.indicators}")
        # TODO: Call your LLM agent here with 'prompt'
        # result = llm_agent.analyze(prompt)
        
        # Example: If investigating an autorun, ask the LLM to assess persistence
        if entity.entity_type == EntityType.AUTORUN_ENTRY:
            logger.info(f"    LLM Prompt: 'Analyze this persistence mechanism: {entity.command_line}'")
            
    def _build_process_prompt(self, entity: Entity) -> str:
        context = f"""
        Process Entity: {entity.name} (PID context from {entity.source_image})
        Path: {entity.path}
        Command Line: {entity.command_line}
        Score: {entity.score}
        Indicators: {', '.join(entity.indicators)}
        """
        return context

    def _build_autorun_prompt(self, entity: Entity) -> str:
        context = f"""
        Persistence Entity: {entity.name}
        Registry Path: {entity.path}
        Command: {entity.command_line}
        Source Image: {entity.source_image}
        Score: {entity.score}
        Indicators: {', '.join(entity.indicators)}
        
        Task: Determine if this is a legitimate startup item or malware persistence.
        Consider: Is the path in a system directory? Is it signed? Is it a LOLBIN?
        """
        return context

    def _build_file_prompt(self, entity: Entity) -> str:
        return f"Anomalous file path detected: {entity.path} (Score: {entity.score})"

    def _correlate_hybrid(self):
        """
        HYBRID MODE ONLY: Correlate memory processes with disk artifacts.
        Example: If a process in memory has the same path as an autorun on disk,
        we have a high-confidence persistence + execution chain.
        """
        if self.mode != EvidenceMode.HYBRID:
            return
        
        procs = [e for e in self.entities if e.entity_type == EntityType.PROCESS]
        autoruns = [e for e in self.entities if e.entity_type == EntityType.AUTORUN_ENTRY]
        
        for proc in procs:
            for ar in autoruns:
                if proc.path and ar.command_line and proc.path.lower() in ar.command_line.lower():
                    logger.info(f"[CORRELATION] Process {proc.name} matches Autorun {ar.name}")
                    proc.add_indicator("Correlated with disk persistence", 2.0)
                    ar.add_indicator("Active in memory", 2.0)

    def run(self):
        """Main state machine loop."""
        if self.mode == EvidenceMode.NONE:
            logger.error("No evidence found. Exiting.")
            sys.exit(1)
        
        # Phase 1: Discovery & Scoring
        self.phase = InvestigationPhase.HEURISTIC_SCORING
        self.entities = get_suspect_entities(self.mode)
        
        if not self.entities:
            if self.mode == EvidenceMode.DISK_ONLY:
                # CRITICAL FIX: If disk-only and no entities, it might be because
                # registry hives haven't been extracted yet. Fall back to bodyfile-only.
                logger.warning("No disk entities scored. Ensure registry hives are extracted.")
                logger.warning("Falling back to bodyfile-only analysis...")
                # Re-run with stricter threshold or different heuristics if needed
            else:
                logger.info("No anomalies crossed the heuristic threshold. Investigation Complete.")
                return
        
        # Phase 2: Entry Point Selection
        self.phase = InvestigationPhase.ENTRY_POINT_SELECTION
        entry_points = self._select_entry_points()
        
        if not entry_points:
            logger.warning("No valid entry points selected for this mode.")
            return
        
        # Phase 3: Deep Investigation
        self.phase = InvestigationPhase.DEEP_INVESTIGATION
        for entity in entry_points:
            self._investigate_entity(entity)
        
        # Phase 4: Hybrid Correlation
        if self.mode == EvidenceMode.HYBRID:
            self.phase = InvestigationPhase.CORRELATION
            self._correlate_hybrid()
            
            # Re-investigate correlated entities with higher scores
            re_score = [e for e in self.entities if e.score >= 7.0 and e.entity_id not in self.investigated_ids]
            for entity in re_score:
                self._investigate_entity(entity)
        
        # Phase 5: Reporting
        self.phase = InvestigationPhase.REPORTING
        logger.info("=" * 60)
        logger.info("Investigation Summary:")
        logger.info(f"  Mode: {self.mode.name}")
        logger.info(f"  Total Entities Scored: {len(self.entities)}")
        logger.info(f"  Entities Investigated: {len(self.investigated_ids)}")
        logger.info("=" * 60)


def main():
    orch = Orchestrator()
    orch.run()


if __name__ == "__main__":
    main()
```

---

## 4. Practical First Step: Hive Extraction Helper

Your `registry_map.json` currently only tells you **where** the hives are. To parse Autoruns, you must extract the actual hive bytes from the disk image. Here is a minimal helper to add to your `extractor.py` that uses `icat` (Sleuth Kit) to pull the hives out so `sieve.py` can parse them.

```python
def extract_registry_hives(bodyfile_path: Path, registry_map_path: Path, disk_image: Path):
    """
    Extract registry hive files from the disk image using Sleuth Kit's icat.
    Places them in CACHE_DIR/hives/<basename>/ so regipy can parse them.
    """
    from pathlib import Path
    import subprocess
    
    cache_hive_dir = CACHE_DIR / "hives" / disk_image.stem
    cache_hive_dir.mkdir(parents=True, exist_ok=True)
    
    with open(registry_map_path) as f:
        regmap = json.load(f)
    
    # Build inode lookup from bodyfile (simplified)
    # In a real implementation, parse the bodyfile to map paths -> inodes
    # For now, this is a placeholder showing the architecture
    
    hives_to_extract = [
        ("SYSTEM", regmap.get("SYSTEM", [])),
        ("SOFTWARE", regmap.get("SOFTWARE", [])),
        ("SAM", regmap.get("SAM", [])),
        ("SECURITY", regmap.get("SECURITY", []))
    ]
    
    for hive_name, entries in hives_to_extract:
        if not entries:
            continue
        # Take the first found instance of the hive
        target_path = entries[0].get("path")
        logger.info(f"Extracting {hive_name} from {disk_image.name}...")
        
        # You need the inode number from the bodyfile or fls output to use icat
        # icat -f ntfs image.dd <inode> > SYSTEM
        # This requires mapping the path to inode first (left as exercise)
        
    return cache_hive_dir
```

**Immediate workaround if you don't have `icat` integration yet:**
The `sieve.py` disk-only mode will still work immediately because `_parse_bodyfile_anomalies()` requires **zero** registry extraction. It scans the `bodyfile` for suspicious paths right now. Once you add hive extraction, the `Autorun` entities will appear automatically.

---

## 5. Summary of Fixes

| Flaw | Fix |
|------|-----|
| **PID-centrism** | Introduced `Entity` abstraction. `sieve.py` now returns `List[Entity]`, not `List[int]`. |
| **Disk-blindness** | `orchestrator.py` detects evidence mode dynamically. Disk-only cases enter via Autoruns/Anomalous Paths instead of PIDs. |
| **Truncation false positive** | `_parse_process_to_entity()` resolves 15-char truncated names using `ImagePathName`/`CmdLine`. Resolved known-good processes are deprioritized. |
| **Cache overwriting** | Already fixed in previous `extractor.py`, but the new orchestrator expects `volatility_*.json`, `bodyfile_*.txt`, and `registry_map_*.json` naming. |
| **Hybrid correlation** | New `_correlate_hybrid()` links active memory processes to disk persistence artifacts for higher-confidence scoring. |

### Honest Architectural Notes

1. **Registry extraction is the bottleneck.** The bodyfile gives you paths and inodes, but you need `icat` or `bulk_extractor` to pull the actual hive bytes. If you cannot extract hives, the disk-only mode still functions via bodyfile heuristics, but you will miss the goldmine of persistence data.
2. **The `regipy` dependency is worth it.** Parsing raw registry hives by hand is error-prone. `regipy` handles transaction logs and deleted keys. If you are constrained to pure Python, `python-registry` is an alternative but less robust.
3. **Entity IDs must be globally unique.** Using `f"PROC_{source_image}_{pid}"` ensures that if you process multiple images, PIDs from different hosts don't collide in the investigation set.
4. **Consider a graph structure.** For hybrid mode, instead of simple correlation loops, you may eventually want a graph where Processes, Files, and Registry keys are nodes with edges representing "created by," "persists via," or "injected into." This is the natural evolution of the Entity model.



Chatgpt

The root problem is not really "disk blindness." It's that your investigation model is built around a single entity type:

```text
PID -> Heuristic Score -> LLM Investigation
```

That works for volatile evidence because processes are the natural graph root. It fails for dead-disk investigations because there may be no processes at all.

I would recommend changing the architecture from a **PID-centric hunter** to an **Entity-centric hunter**.

---

# 1. Refactor the Sieve: PIDs Become One Entity Type

Instead of:

```python
suspect_pids = sieve()
```

move to:

```python
suspect_entities = sieve()
```

where every finding is normalized into a common schema.

```python
{
    "entity_type": "process",
    "entity_id": "2480",
    "score": 87,
    "reasons": [
        "malfind hit",
        "network connection",
        "suspicious parent"
    ],
    "evidence": {...}
}
```

Disk findings become:

```python
{
    "entity_type": "autorun",
    "entity_id": r"HKLM\...\Run\Updater",
    "score": 75,
    "reasons": [
        "user-writable path",
        "temp directory execution"
    ],
    "evidence": {...}
}
```

Or:

```python
{
    "entity_type": "file",
    "entity_id": r"C:\Users\Bob\AppData\Roaming\svchost.exe",
    "score": 90,
    "reasons": [
        "masquerading",
        "unusual location"
    ]
}
```

The LLM should never care whether the entity originated from memory or disk.

---

# 2. New Entity Model

I would define:

```python
class InvestigationEntity:

    def __init__(
        self,
        entity_type,
        entity_id,
        score,
        reasons,
        evidence
    ):
        self.entity_type = entity_type
        self.entity_id = entity_id
        self.score = score
        self.reasons = reasons
        self.evidence = evidence
```

Supported types:

```text
process
autorun
registry_key
registry_value
file
prefetch
amcache_entry
scheduled_task
service
user_account
network_connection
```

Now the orchestrator no longer needs PIDs.

It needs:

```python
high_risk_entities
```

---

# 3. Sieve Architecture

Split into independent analyzers.

```python
def sieve():

    entities = []

    entities.extend(memory_sieve())

    entities.extend(registry_sieve())

    entities.extend(bodyfile_sieve())

    entities.extend(prefetch_sieve())

    entities.extend(amcache_sieve())

    return sorted(
        entities,
        key=lambda x: x.score,
        reverse=True
    )
```

This immediately supports:

### Memory-only

```text
memory_sieve() returns findings
disk analyzers return []
```

### Disk-only

```text
memory_sieve() returns []
registry_sieve() returns findings
```

### Hybrid

```text
all analyzers contribute
```

No branching required.

---

# 4. Dynamic Investigation Modes

Current:

```python
if not suspect_pids:
    exit()
```

Replace with:

```python
entities = sieve()

if not entities:
    print("No suspicious entities found")
    return
```

Then:

```python
for entity in entities:

    investigate_entity(entity)
```

---

# 5. Investigation State Machine

Current state machine:

```text
PROCESS
   ↓
PID
   ↓
LLM
```

New:

```text
ENTITY
   ↓
Context Builder
   ↓
LLM
   ↓
Expand Related Entities
```

Example:

---

Memory case

```text
PID 2480

find parent
find sockets
find injected code

LLM
```

---

Disk case

```text
Autorun Key

find referenced file
find file metadata
find prefetch
find amcache

LLM
```

Same state machine.

Different expansion logic.

---

# 6. First Disk Trigger: Autoruns

This is probably the highest ROI.

You already have:

```text
registry_map.json
```

containing:

```text
SYSTEM
SOFTWARE
NTUSER.DAT
```

Extract:

```text
HKLM\Software\Microsoft\Windows\CurrentVersion\Run

HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

HKCU\Software\Microsoft\Windows\CurrentVersion\Run

HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

and:

```text
Services

Winlogon Shell

Userinit

AppInit_DLLs

IFEO
```

---

Example parser output:

```python
{
    "type": "autorun",
    "key":
      r"HKCU\...\Run",
    "name":
      "WindowsUpdate",
    "data":
      r"C:\Users\Bob\AppData\Roaming\update.exe"
}
```

Then score it.

---

# 7. Autorun Heuristics

Example scoring:

```python
score = 0
```

Temp path:

```python
if "\\temp\\" in path.lower():
    score += 50
```

AppData executable:

```python
if "\\appdata\\" in path.lower():
    score += 30
```

Randomized filename:

```python
if looks_random(filename):
    score += 20
```

Masquerading:

```python
if filename.lower() == "svchost.exe":
    score += 40
```

Unsigned path:

```python
if not path.startswith(
    r"C:\Windows"
):
    score += 10
```

Create entity:

```python
entities.append(
    InvestigationEntity(
        entity_type="autorun",
        entity_id=path,
        score=score,
        reasons=reasons,
        evidence=record
    )
)
```

---

# 8. Bodyfile Heuristics

You already generate bodyfiles.

Look for:

### Executables in user-writable locations

```text
\AppData\
\Temp\
\Downloads\
\Desktop\
```

### LOLBIN staging

```text
rundll32.exe
regsvr32.exe
mshta.exe
wscript.exe
cscript.exe
```

### Double extensions

```text
invoice.pdf.exe
```

### Suspicious creation times

```text
clustered file creation
```

Create file entities.

```python
{
    "entity_type": "file",
    "entity_id": path,
    ...
}
```

---

# 9. Future Expansion

Add:

```text
Amcache
```

to identify executed binaries.

Create:

```python
entity_type="executed_file"
```

Add:

```text
Prefetch
```

to identify program execution.

Create:

```python
entity_type="prefetch"
```

Add:

```text
Scheduled Tasks
```

Create:

```python
entity_type="task"
```

The orchestrator remains unchanged.

---

# 10. Fixing the Truncated Process False Positive

This is important.

Many Volatility plugins truncate process names.

Examples:

```text
VeryLongMalwareLoader.exe
```

becomes:

```text
VeryLongMalwa...
```

or

```text
VeryLongMalwa
```

depending on the plugin.

Your current logic likely contains something similar to:

```python
if process_name.endswith("..."):
    score += 50
```

or:

```python
if process_name not in KNOWN_PROCESSES:
    suspicious
```

which will generate false positives.

---

## Better Rule

Treat truncation as an uncertainty signal, not a malicious signal.

```python
if name.endswith("..."):
    confidence *= 0.5
```

or

```python
flags.append("truncated_name")
```

but:

```python
score += 0
```

---

## Cross-Validate

Use:

```text
pstree
pslist
cmdline
handles
```

to recover the full image path.

Example:

```python
pid = proc["PID"]

cmdline = cmdline_cache.get(pid)

if cmdline:
    proc["full_name"] = cmdline
```

Now score:

```python
cmdline.exe
```

instead of:

```python
cmdlin...
```

---

## Confidence-Aware Scoring

Instead of:

```python
score += 40
```

use:

```python
score += 40 * confidence
```

where:

```python
confidence = 1.0
```

and:

```python
if truncated:
    confidence = 0.5
```

This dramatically reduces false positives caused by Volatility artifacts.

---

# Recommended End State

Refactor the DFIR engine from:

```text
PID-Centric
───────────
Volatility
   ↓
Suspect PIDs
   ↓
LLM
```

to:

```text
Entity-Centric
──────────────
Memory Findings
Disk Findings
Registry Findings
Prefetch Findings
Amcache Findings
        ↓
Unified Sieve
        ↓
Suspect Entities
        ↓
LLM Investigation
        ↓
Evidence Expansion Graph
```

Once you make that shift, memory-only, disk-only, and hybrid investigations all flow through the same orchestration path, and the agent no longer depends on active processes existing in the evidence set.

