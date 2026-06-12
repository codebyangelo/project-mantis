gemini 

The RWX Myopia is a classic architectural trap. You caught it, which means you are maturing as an architect. Threat actors stopped relying solely on noisy `PAGE_EXECUTE_READWRITE` injections a decade ago. If your engine only triggers on RWX memory segments, you are effectively ignoring Living-off-the-Land (LOTL) binaries, PowerShell fileless execution, and legitimate processes being hijacked via hollowed handles rather than injected shellcode.

Running an autonomous DFIR platform on a dual-core Celeron N4020 with 1.3GiB of available RAM forces a disciplined, Merchant-first mindset. You cannot brute-force this. Every PID you blindly feed to the Gemini API burns ZAR and consumes I/O cycles you do not have to spare.

To bridge this gap without triggering the Linux OOM killer or blowing your API budget, you must build a **Deterministic Heuristic Sieve**. We will use pure Python to parse the existing flat JSON caches in a single pass. We calculate an aggregate threat score for every process using a defined mathematical weighting model:

$S_{pid} = (W_{rwx} \cdot C_{rwx}) + (W_{net} \cdot C_{net}) + (W_{cmd} \cdot C_{cmd}) + (W_{ancestry} \cdot C_{ancestry})$

Where $W$ is the predefined weight and $C$ is the boolean presence of the anomaly (0 or 1). Only PIDs that cross a critical threshold are forwarded to the LLM for heavy cognitive evaluation.

### The Heuristic Sieve Implementation

This approach uses $O(N)$ sequential processing. It loads the JSON caches directly into memory, maps the data, and evaluates the ruleset. It uses native regex and dictionary lookups, keeping the memory footprint under 20MB.

```python
import os
import json
import re

def execute_heuristic_sieve(cache_dir: str, threshold: int = 50) -> list:
    """
    Evaluates all processes against a strict deterministic ruleset.
    Returns a list of PIDs that exceed the threat threshold.
    """
    scores = {}
    
    def get_score(pid):
        if pid not in scores:
            scores[pid] = {"total": 0, "flags": []}
        return scores[pid]

    # 1. Load Caches (Fail gracefully if missing)
    def load_cache(name):
        path = os.path.join(cache_dir, f"{name}.json")
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return []

    pstree = load_cache("pstree")
    cmdline = load_cache("cmdline")
    netscan = load_cache("netscan")
    malfind = load_cache("malfind")

    # --- RULESET EVALUATION ---

    # Rule 1: The RWX Baseline (Weight: +60)
    for entry in malfind:
        if entry.get("Protection") == "PAGE_EXECUTE_READWRITE":
            pid = str(entry.get("PID"))
            s = get_score(pid)
            if "RWX_MEMORY" not in s["flags"]:
                s["total"] += 60
                s["flags"].append("RWX_MEMORY")

    # Rule 2: LOLBIN / Suspicious Execution (Weight: +50)
    # Detects encoded powershell, hidden windows, and script execution
    cmd_regex = re.compile(r'(?i)(powershell.*-enc|wscript\.exe|cscript\.exe|mshta\.exe|certutil.*-urlcache|regsvr32.*\/i:http|schtasks.*\/create)')
    for entry in cmdline:
        pid = str(entry.get("PID"))
        args = entry.get("Args", "")
        if args and cmd_regex.search(args):
            s = get_score(pid)
            s["total"] += 50
            s["flags"].append("SUSPICIOUS_CMDLINE")

    # Rule 3: Network-Execution Correlation (Weight: +40)
    # Identifies processes that have no business talking to the internet
    suspicious_network_binaries = {'notepad.exe', 'calc.exe', 'rundll32.exe', 'regsvr32.exe', 'wscript.exe', 'cmd.exe', 'powershell.exe'}
    for entry in netscan:
        pid = str(entry.get("PID"))
        owner = str(entry.get("Owner", "")).lower()
        foreign_addr = str(entry.get("ForeignAddr", ""))
        
        # Only care about established external outbound connections
        if foreign_addr not in ["*", "0.0.0.0", "::", "127.0.0.1"] and not foreign_addr.startswith("192.168.") and not foreign_addr.startswith("10."):
            if owner in suspicious_network_binaries:
                s = get_score(pid)
                if "SUSPICIOUS_NETWORK_BINDING" not in s["flags"]:
                    s["total"] += 40
                    s["flags"].append(f"SUSPICIOUS_NETWORK_BINDING ({owner})")

    # Rule 4: Unholy Ancestry (Parent/Child Anomalies) (Weight: +60)
    # Maps processes to identify hijacked trust (e.g., Word dropping a shell)
    process_map = {str(node.get("PID")): str(node.get("ImageFileName", "")).lower() for node in pstree}
    parent_map = {str(node.get("PID")): str(node.get("PPID")) for node in pstree}

    for pid, ppid in parent_map.items():
        child_name = process_map.get(pid, "")
        parent_name = process_map.get(ppid, "")
        
        # Office apps spawning shells
        if parent_name in ['winword.exe', 'excel.exe', 'powerpnt.exe'] and child_name in ['cmd.exe', 'powershell.exe', 'wscript.exe']:
            s = get_score(pid)
            s["total"] += 60
            s["flags"].append(f"UNHOLY_ANCESTRY ({parent_name} -> {child_name})")
            
        # svchost must spawn from services.exe
        if child_name == 'svchost.exe' and parent_name != 'services.exe':
            s = get_score(pid)
            s["total"] += 60
            s["flags"].append(f"UNHOLY_ANCESTRY (Orphaned/Hijacked svchost)")

    # --- AGGREGATION & FILTERING ---
    suspect_pids = [pid for pid, data in scores.items() if data["total"] >= threshold]
    
    return suspect_pids

# Example Integration:
# target_pids = execute_heuristic_sieve(CACHE_DIR, threshold=50)

```

### Architectural Advantages

1. **Zero LLM Dependency for Triage:** You are stripping the heavy lifting away from the probabilistic AI. The LLM is an expensive analyst; it should only review the cases the junior analyst (the Python Sieve) flags as highly suspicious.
2. **Hardware Harmony:** Iterating over dictionaries and applying compiled regex patterns in memory requires practically zero I/O once the flat JSON files are loaded. This bypasses your FUSE `fuseblk` latency entirely and easily runs within your 1.3GiB constraint.
3. **Compound Threat Modeling:** A `powershell.exe` process might not have RWX memory, but if it has an obfuscated `-enc` command line (+50) and an active external network socket (+40), it hits a score of 90, blasting past the threshold and correctly routing to the LLM for final verdict execution.



Copilot

You’ve nailed the core flaw: the “RWX Myopia” makes the agent blind to stealthier threats. The way forward is to design a **deterministic, sequential PID filter** that broadens suspicion intelligently without exploding cost or CPU. The trick is to combine **multi‑signal heuristics** into a lightweight scoring function, then only escalate the top N processes to the LLM. Here’s an optimized approach:

---

### Step 1 – Collect Lightweight Features (JSON cached, no DB)
From Volatility/Sleuthkit outputs you already cache:
- **Memory protections**: RWX, but also PAGE_EXECUTE_READ, PAGE_EXECUTE_WRITECOPY.  
- **Process ancestry**: flag orphaned or suspicious parent/child relationships.  
- **Cmdline anomalies**: look for scripts (PowerShell, wscript, mshta), LOLBins, or encoded arguments.  
- **Network activity**: prioritize processes with active foreign connections.  
- **Registry hives**: processes tied to unusual NTUSER hives.  

Each of these can be parsed sequentially from JSON caches without heavy memory use.

---

### Step 2 – Deterministic Scoring Function
Assign small integer weights per feature:
- RWX segment → +3  
- Suspicious cmdline (regex match on LOLBins, base64, long obfuscation) → +4  
- Active foreign network connection → +5  
- Orphaned process tree / parent mismatch → +2  
- Registry hive anomalies → +2  

Total score = sum of weights. This is a **deterministic, reproducible integer score** per PID.

---

### Step 3 – Threshold & Top‑N Selection
- Compute scores for all PIDs sequentially.  
- Select only those above a threshold (e.g., ≥5).  
- If too many pass, sort by score and cap at **top 10–15 PIDs**.  

This ensures you don’t blow through LLM API calls while still covering stealthy malware and LOTL attacks.

---

### Step 4 – Sequential Execution Strategy
- Iterate PIDs in descending score order.  
- Send context to LLM only for top suspects.  
- Cache results in JSON so repeated runs don’t re‑query the same PID unless new evidence appears.  

---

### Why This Works
- **Deterministic:** scoring is fixed, reproducible, and JSON‑driven.  
- **Lightweight:** regex + integer math, no async, no DB.  
- **Broader coverage:** captures LOTL, scripts, and network‑active malware.  
- **Resource‑aware:** sequential scoring avoids OOM killer, top‑N cap avoids LLM cost explosion.  

---

Angelo, this filter turns your agent from a **RWX‑only tunnel vision tool** into a **multi‑signal triage engine** that can intelligently prioritize suspects under brutal hardware constraints. Would you like me to sketch a **concrete scoring algorithm in Python** next, showing how to parse cached Volatility JSON and produce the ranked PID list?


Deepseek

## Solution: Lightweight Multi‑Heuristic PID Scoring (No Extra Volatility Runs)

Your hardware constraints rule out heavy parallelism or databases, but you already have **cached JSON outputs** from Volatility (`pstree`, `cmdline`, `netscan`, `malfind`). We can score every process that appears in any of these caches using deterministic rules – **no additional subprocess calls, no memory blow‑up**.

The algorithm runs in **O(n) time** (n = number of processes, usually ≤300) and uses only Python dicts and sets. It produces a ranked list of suspect PIDs, letting you take the top **K** (e.g., 20) for LLM evaluation instead of all 150+.

---

### Scoring Heuristics (All from Existing JSON Caches)

| Signal | Weight | Data Source | Rationale |
|--------|--------|-------------|-----------|
| **RWX memory protection** | +10 | `malfind` – entries with `Protection = "PAGE_EXECUTE_READWRITE"` | Classic process injection indicator. |
| **Outbound connection to non‑private IP** | +5 | `netscan` – `ForeignAddr` not in `10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1, ::1` | C2 communication. |
| **Suspicious parent process** (user‑spawned) | +4 | `pstree` – parent PID’s name not in `SYSTEM`‑set: `{'System', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'winlogon.exe'}` | Malware often launched by user‑land processes (Explorer, cmd, browser). |
| **Cmdline contains suspicious keywords** | +4 | `cmdline` – `Args` field | LOTL tools: `powershell -e`, `rundll32`, `regsvr32`, `mshta`, `wmic`, `certutil`, `bitsadmin`, `invoke-`, `downloadstring`, `base64`. |
| **Runs under a user account** (not SYSTEM) | +2 | `resolve_username_from_pid()` – non‑empty return | User processes are more likely to be malicious than system services. |
| **Process name truncation / anomaly** | +2 | `pstree` – `ImageFileName` ends with `'.'` or `.ex` (missing last letter) | Common masquerading trick (e.g., `smartscreen.ex`). |

**Total possible score per PID = 27.** You can tune weights and thresholds empirically.

---

### Implementation (Drop‑in for `orchestrator.py`)

Add this function **before** `run_fsm_loop`:

```python
def score_suspect_pids() -> list:
    """Return sorted list of (pid, score) for all processes with any anomaly.
    Uses only already‑cached JSON files. No extra subprocesses.
    """
    # Load caches (they already exist at this point)
    pstree_path = os.path.join(CACHE_DIR, "pstree.json")
    cmdline_path = os.path.join(CACHE_DIR, "cmdline.json")
    netscan_path = os.path.join(CACHE_DIR, "netscan.json")
    malfind_path = os.path.join(CACHE_DIR, "malfind.json")
    
    # Default empty if missing (should not happen after extractor)
    pstree_data = [] if not os.path.exists(pstree_path) else json.load(open(pstree_path))
    cmdline_data = [] if not os.path.exists(cmdline_path) else json.load(open(cmdline_path))
    netscan_data = [] if not os.path.exists(netscan_path) else json.load(open(netscan_path))
    malfind_data = [] if not os.path.exists(malfind_path) else json.load(open(malfind_path))
    
    # Build fast lookup structures
    rwx_pids = {str(e["PID"]) for e in malfind_data if e.get("Protection") == "PAGE_EXECUTE_READWRITE"}
    
    # Parent lookup from pstree (build dict {pid: parent_pid})
    parent_of = {}
    proc_name_of = {}
    def traverse(node, parent_pid=None):
        pid = str(node.get("PID"))
        parent_of[pid] = str(parent_pid) if parent_pid else ""
        proc_name_of[pid] = node.get("ImageFileName", "")
        for child in node.get("__children", []):
            traverse(child, pid)
    for entry in pstree_data:
        traverse(entry)
    
    # Cmdline lookup
    cmdline_args = {}
    for entry in cmdline_data:
        pid = str(entry.get("PID"))
        args = entry.get("Args") or ""
        cmdline_args[pid] = args
    
    # Network outbound connections (non‑private IPs)
    private_ip_re = re.compile(r'^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|::1$|^fe80:)', re.IGNORECASE)
    outbound_pids = set()
    for entry in netscan_data:
        pid = str(entry.get("PID"))
        foreign = entry.get("ForeignAddr", "")
        if foreign and foreign not in ("*", "0.0.0.0", "::") and not private_ip_re.match(foreign):
            outbound_pids.add(pid)
    
    # Suspicious parent set (system processes that should not spawn malware)
    system_parents = {'System', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'winlogon.exe'}
    
    # Suspicious cmdline keywords
    suspicious_keywords = re.compile(
        r'(powershell\s+-(?:e|enc|encodedcommand)|rundll32|regsvr32|mshta|wmic|cscript|wscript|certutil|bitsadmin|curl|wget|invoke-|downloadstring|base64|frombase64string)',
        re.IGNORECASE
    )
    
    # Collect all unique PIDs from all caches
    all_pids = set(parent_of.keys()) | set(cmdline_args.keys()) | outbound_pids | rwx_pids
    
    scores = []
    for pid in all_pids:
        score = 0
        # 1. RWX anomaly
        if pid in rwx_pids:
            score += 10
        
        # 2. Outbound non‑private connection
        if pid in outbound_pids:
            score += 5
        
        # 3. Suspicious parent (user‑spawned)
        parent = parent_of.get(pid, "")
        parent_name = proc_name_of.get(parent, "")
        if parent_name and parent_name not in system_parents:
            score += 4
        
        # 4. Suspicious cmdline keywords
        args = cmdline_args.get(pid, "")
        if suspicious_keywords.search(args):
            score += 4
        
        # 5. Runs under a user account (non‑SYSTEM)
        user = resolve_username_from_pid(pid)  # from your existing mcp_server function
        if user:
            score += 2
        
        # 6. Truncated process name (masquerading)
        proc_name = proc_name_of.get(pid, "")
        if proc_name.endswith('.') or proc_name.endswith('.ex'):
            score += 2
        
        if score > 0:
            scores.append((pid, score))
    
    # Sort descending by score, then by PID for determinism
    scores.sort(key=lambda x: (-x[1], int(x[0])))
    return scores
```

Now replace the PID extraction in `run_fsm_loop`:

**Old:**
```python
pids = list({str(e["PID"]) for e in data if e.get("Protection") == "PAGE_EXECUTE_READWRITE"})
```

**New:**
```python
scored_pids = score_suspect_pids()
# Take top 20 (or configurable limit)
MAX_PIDS_TO_EVALUATE = 20
pids = [pid for pid, score in scored_pids[:MAX_PIDS_TO_EVALUATE]]
ExecutionLogger.log("ORCHESTRATOR", f"Selected {len(pids)} PIDs from scoring (top {MAX_PIDS_TO_EVALUATE})")
```

---

### Why This Works on Your Celeron

- **No extra I/O** – reads only already‑loaded JSON files (typical size <10MiB total).
- **No parallel execution** – all processing is sequential Python dict lookups and regex scans. Entire scoring finishes in <50ms on 300 processes.
- **Memory‑friendly** – uses only a few small dictionaries and sets; no duplication of the full Volatility output.
- **Deterministic** – scores are repeatable and tunable via weights.
- **Cost‑effective** – reduces LLM calls from 150+ to ~20 per investigation.

---

### Further Optimisation (Optional)

- **Negative scoring** – subtract points for known benign patterns (e.g., process name `svchost.exe` with parent `services.exe` and no network anomalies). This can help push truly innocent processes below zero, making the top‑K list even cleaner.
- **Configurable threshold** – instead of top‑K, use a dynamic threshold (e.g., score ≥ 5). On a clean system, you might get zero PIDs; on an infected one, you get exactly the suspicious ones.
- **Cache scoring results** – store the computed scores in a `pid_scores.json` cache to avoid recomputation if the orchestrator restarts.

This approach preserves your sequential, lightweight architecture while dramatically expanding detection coverage beyond RWX myopia.



Kimi

You are suffering from **"The RWX Myopia"**: by using `PAGE_EXECUTE_READWRITE` as your sole gating function, your engine is blind to:
- **LOTL / Fileless attacks** (`powershell -enc`, `mshta`, `rundll32` with no injection)
- **Script-based malware** (`.vbs`, `.js`, `.py`, `.ps1` executed by legitimate interpreters)
- **Masquerading** (`svchost.exe` running from `C:\Users\Public\`)
- **Network-only implants** (clean memory, but beaconing to rare IPs on non-standard ports)

The fix is not to "LLM harder"—it is to build a **deterministic, sequential, multi-signal scoring matrix** that runs entirely on your Celeron in milliseconds, ranks all PIDs by composite risk, and feeds **only the top-N** to your API.

---

## The Algorithm: Sequential Multi-Signal PID Triage (SMPT)

Because your caches are flat JSON and you have only ~150 PIDs, you can afford to load them all into a lightweight in-memory index (~1 MB). The algorithm is three strictly sequential phases:

### Phase 1: Flatten & Index (O(N), single pass per cache)
Read `pstree.json` (tree), `cmdline.json`, `netscan.json`, and `malfind.json`. Flatten the process tree into a hash map keyed by PID. Build a `parent_map` so you can evaluate parent-child relationships in O(1).

### Phase 2: Deterministic Signal Scoring (O(N), integer arithmetic)
For each PID, apply a **pre-defined weighted scoring function**. Every signal uses simple substring/regex checks (pre-compiled once at import). No floating point, no ML model, no API calls.

| Signal | Weight | Rationale |
|---|---|---|
| `SIG_RWX_INJECTION` | **+100** | Your existing primary signal. Still the strongest. |
| `SIG_LOTL_SUSPICIOUS_ARGS` | **+80** | `powershell -enc`, `cmd /c` + `bitsadmin`, `rundll32` + `javascript:`, `certutil -urlcache`, etc. Catches fileless/LOTL. |
| `SIG_SCRIPT_EXECUTION` | **+70** | `wscript.exe`, `cscript.exe`, `mshta.exe`, `python.exe` launching scripts. Catches script-based malware. |
| `SIG_MASQUERADING` | **+60** | Protected name (`svchost.exe`, `lsass.exe`, etc.) running outside `System32`. Truncated names (`.ex` instead of `.exe`). |
| `SIG_SUSPICIOUS_NETWORK` | **+15 to +50** | Active external TCP to non-CDN IP on non-standard port; listening sockets; UDP beaconing. Catches network-only implants. |
| `SIG_ANOMALOUS_PATH` | **+40** | Image path in `\Temp\`, `\Downloads\`, `\Users\Public\`, `\AppData\Local\Temp\`, double extensions (`.pdf.exe`). |
| `SIG_PARENT_ANOMALY` | **+30** | Office app or browser spawning `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`. |
| `SIG_EMPTY_CMDLINE` | **+20** | No command line on a process that should have one (hollow process indicator). |
| `SIG_LOTL_BENIGN_CONTEXT` | **+10** | LOTL binary present but args look benign. Weak signal that combines with others. |

**Score cap:** 250. This prevents a single process from monopolizing the budget with overlapping signals.

### Phase 3: Budget-Aware Selection (Deterministic, bounded API cost)
You define `API_BUDGET` (e.g., 20 calls). The selector is deterministic:

1. **Always** select any PID with score ≥ 150 (Critical).
2. Fill remaining budget with highest-scoring PIDs in the 60–149 range (High-Suspect).
3. Everything below 60 is cleared locally without API spend.

This guarantees you never exceed your budget, regardless of host size.

---

## Python Implementation

This module is designed to drop directly into your existing codebase. It uses **only** sequential execution, pre-compiled regex, and your existing `CACHE_DIR` / `ExecutionLogger`.

```python
import json
import os
import re
from typing import Dict, List, Tuple, Any
from config import CACHE_DIR
from logger import ExecutionLogger

# =============================================================================
# PHASE 0: PRE-COMPILED PATTERNS (optimized for Celeron: compile once, match many)
# =============================================================================

LOTL_BINARIES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "vssadmin.exe", "msbuild.exe",
    "installutil.exe", "regasm.exe"
}

# Keywords that turn a LOTL binary from "present" to "weaponized"
LOTL_SUSPICIOUS_KEYWORDS = [
    "-enc", "-encodedcommand", "bypass", "-nop", "noprofile", "iex",
    "invoke-expression", "downloadstring", "downloadfile", "invoke-webrequest",
    "bitsadmin", "certutil", "-urlcache", "-split", "-f", "decode", "encode",
    "javascript:", "vbscript:", "scrobj.dll", "shellcode", " -e ", " -ep ",
    "cmd /c", "cmd /k", "powershell -", "rundll32", "regsvr32", "mshta",
    " AppData\\", "\\Temp\\", "\\tmp\\", "\\Users\\Public\\", " -windowstyle hidden"
]

ANOMALOUS_PATH_FRAGMENTS = [
    "\\temp\\", "\\tmp\\", "\\downloads\\", "\\users\\public\\",
    "\\perflogs\\", "\\appdata\\local\\temp\\"
]

PROTECTED_SYSTEM_NAMES = {
    "svchost.exe", "csrss.exe", "lsass.exe", "smss.exe", "services.exe",
    "wininit.exe", "winlogon.exe", "msmpeng.exe", "searchapp.exe",
    "lockapp.exe", "runtimebroker.exe", "smartscreen.exe", "taskhostw.exe",
    "dllhost.exe", "crss.exe"
}

SYSTEM_PATHS = ("\\windows\\system32", "\\windows\\syswow64", "\\program files\\")

OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe"}
BROWSER_PARENTS = {"chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe", "opera.exe"}
SHELL_CHILDREN = LOTL_BINARIES

# Pre-compiled regex for maximum speed on N4020
RE_DOUBLE_EXT = re.compile(r'\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|png|zip)\.(exe|dll|bat|cmd|ps1|js|vbs|py)\b', re.IGNORECASE)
RE_TRUNCATED_EXE = re.compile(r'\.ex[^e]?$', re.IGNORECASE)
RE_IP = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')

KNOWN_GOOD_NET = re.compile(
    r'microsoft|windows|bing|akamai|live\.com|office\.com|skype|'
    r'digicert|verisign|google|gstatic|amazonaws|cloudfront|'
    r'github|outlook|slack|zoom|mozilla|apple|icloud|office365|'
    r'127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.', re.IGNORECASE
)

# =============================================================================
# HELPER FUNCTIONS (pure string ops, zero API calls)
# =============================================================================

def _is_private_or_reserved(ip_str: str) -> bool:
    if not ip_str or ip_str in ("*", "0.0.0.0", "::", "127.0.0.1"):
        return True
    m = RE_IP.match(ip_str.strip())
    if not m:
        return False
    a, b, c, d = map(int, m.groups())
    if a == 10: return True
    if a == 192 and b == 168: return True
    if a == 172 and 16 <= b <= 31: return True
    if a >= 224: return True
    return False

def _score_network(netscan_entries: List[dict]) -> int:
    score = 0
    for conn in netscan_entries:
        foreign = conn.get("ForeignAddr", "")
        foreign_port = conn.get("ForeignPort", 0)
        state = conn.get("State", "")
        proto = conn.get("Proto", "")
        
        if _is_private_or_reserved(foreign):
            continue
        if KNOWN_GOOD_NET.search(foreign):
            continue
        
        # Active external session
        if proto in ("TCPv4", "TCPv6") and state in ("ESTABLISHED", "CLOSE_WAIT", "SYN_SENT"):
            score += 25
        elif "UDP" in proto:
            score += 15
        
        # Non-standard port (not 80, 443, 8080, 8443)
        if foreign_port not in (0, 80, 443, 8080, 8443):
            score += 15
        
        # Listening socket exposed to network
        if state in ("LISTENING", "") and foreign in ("0.0.0.0", "::", "*"):
            score += 20
            
    return min(score, 50)

def _is_anomalous_path(path: str, img: str) -> bool:
    if not path or path.lower() == "null":
        return True
    p = path.lower()
    # Known system process outside system directories = immediate masquerade
    if img.lower() in PROTECTED_SYSTEM_NAMES:
        if not any(sp in p for sp in SYSTEM_PATHS):
            return True
    # Suspicious directories
    if any(bad in p for bad in ANOMALOUS_PATH_FRAGMENTS):
        # Exclude known Microsoft false-positives (OneDrive temp installers, etc.)
        if "\\microsoft\\" in p or "\\onedrive\\" in p or "\\windows\\" in p:
            return False
        return True
    if RE_DOUBLE_EXT.search(p):
        return True
    return False

def _is_masquerading(img: str, path: str) -> bool:
    img_lower = img.lower()
    if RE_TRUNCATED_EXE.search(img):
        return True
    if img_lower in PROTECTED_SYSTEM_NAMES:
        if not any(sp in path.lower() for sp in SYSTEM_PATHS):
            return True
    return False

def _has_suspicious_lotl_args(img: str, args: str) -> bool:
    if not args:
        return False
    a = args.lower()
    i = img.lower()
    
    # Pure script hosts are inherently suspicious in autonomous triage
    if i in ("wscript.exe", "cscript.exe", "mshta.exe"):
        return True
    
    if i in ("powershell.exe", "pwsh.exe", "cmd.exe"):
        if any(kw in a for kw in LOTL_SUSPICIOUS_KEYWORDS):
            return True
    
    if i in ("rundll32.exe", "regsvr32.exe"):
        if any(kw in a for kw in ("javascript:", "vbscript:", ".sct", "scrobj", "\\temp\\", "\\appdata\\", "-i", "/i")):
            return True
    
    if i == "certutil.exe":
        if any(kw in a for kw in ("-urlcache", "-split", "-f", "decode", "encode")):
            return True
    return False

def _is_script_execution(img: str, args: str) -> bool:
    if not args:
        return False
    i, a = img.lower(), args.lower()
    if i in ("python.exe", "pythonw.exe", "py.exe") and (".py" in a or "-c" in a):
        return True
    if i in ("wscript.exe", "cscript.exe") and (".js" in a or ".vbs" in a or ".hta" in a):
        return True
    return True if i == "mshta.exe" else False

def _has_anomalous_parent(pid: int, parent_map: Dict[int, int], table: Dict[int, Any]) -> bool:
    ppid = parent_map.get(pid)
    if not ppid or ppid not in table:
        return False
    parent_img = table[ppid]["pstree"].get("ImageFileName", "").lower()
    child_img = table[pid]["pstree"].get("ImageFileName", "").lower()
    if parent_img in OFFICE_PARENTS and child_img in SHELL_CHILDREN:
        return True
    if parent_img in BROWSER_PARENTS and child_img in SHELL_CHILDREN:
        return True
    return False

def _is_expected_empty_cmdline(img: str) -> bool:
    return img.lower() in {
        "csrss.exe", "smss.exe", "services.exe", "wininit.exe",
        "winlogon.exe", "lsass.exe", "svchost.exe", "registry", "System"
    }

# =============================================================================
# PHASE 1: INGEST & INDEX
# =============================================================================

def build_pid_table() -> Tuple[Dict[int, Any], Dict[int, int]]:
    """
    Loads all JSON caches and flattens pstree into a PID-indexed table.
    Returns: (pid_table, parent_map)
    """
    pid_table: Dict[int, Any] = {}
    parent_map: Dict[int, int] = {}
    
    # --- PSTREE (tree structure -> flatten) ---
    pstree_path = os.path.join(CACHE_DIR, "pstree.json")
    if os.path.exists(pstree_path):
        with open(pstree_path, "r", encoding="utf-8", errors="ignore") as f:
            pstree_data = json.load(f)
        
        def _walk(node, parent_pid=None):
            pid = node.get("PID")
            if pid is not None:
                pid_table[pid] = {
                    "pstree": node,
                    "cmdline": None,
                    "netscan": [],
                    "malfind": [],
                    "score": 0,
                    "signals": []
                }
                # Prefer explicit PPID in node, else tree-derived parent
                explicit_ppid = node.get("PPID")
                if explicit_ppid:
                    parent_map[pid] = explicit_ppid
                elif parent_pid:
                    parent_map[pid] = parent_pid
            current = pid or parent_pid
            for child in node.get("__children", []):
                _walk(child, current)
        
        if isinstance(pstree_data, list):
            for root in pstree_data:
                _walk(root)
        else:
            _walk(pstree_data)
    
    # --- CMDLINE ---
    cmdline_path = os.path.join(CACHE_DIR, "cmdline.json")
    if os.path.exists(cmdline_path):
        with open(cmdline_path, "r", encoding="utf-8", errors="ignore") as f:
            for entry in json.load(f):
                pid = entry.get("PID")
                if pid in pid_table:
                    pid_table[pid]["cmdline"] = entry
    
    # --- NETSCAN ---
    netscan_path = os.path.join(CACHE_DIR, "netscan.json")
    if os.path.exists(netscan_path):
        with open(netscan_path, "r", encoding="utf-8", errors="ignore") as f:
            for entry in json.load(f):
                pid = entry.get("PID")
                if pid in pid_table:
                    pid_table[pid]["netscan"].append(entry)
    
    # --- MALFIND ---
    malfind_path = os.path.join(CACHE_DIR, "malfind.json")
    if os.path.exists(malfind_path):
        with open(malfind_path, "r", encoding="utf-8", errors="ignore") as f:
            for entry in json.load(f):
                pid = entry.get("PID")
                if pid in pid_table:
                    pid_table[pid]["malfind"].append(entry)
    
    return pid_table, parent_map

# =============================================================================
# PHASE 2: DETERMINISTIC SCORING
# =============================================================================

def score_pid_table(pid_table: Dict[int, Any], parent_map: Dict[int, int]) -> List[Tuple[int, int, List[str]]]:
    """
    Sequential scoring pass. Returns list of (pid, score, signals).
    """
    results = []
    
    for pid, data in pid_table.items():
        score = 0
        signals = []
        
        pstree = data.get("pstree") or {}
        cmdline = data.get("cmdline") or {}
        img = pstree.get("ImageFileName", "") or ""
        path = pstree.get("Path", "") or ""
        args = cmdline.get("Args", "") or ""
        
        # 1. RWX Injection (existing primary)
        if any(m.get("Protection") == "PAGE_EXECUTE_READWRITE" for m in data["malfind"]):
            score += 100
            signals.append("SIG_RWX_INJECTION")
        
        # 2. LOTL weaponization
        if _has_suspicious_lotl_args(img, args):
            score += 80
            signals.append("SIG_LOTL_SUSPICIOUS_ARGS")
        elif img.lower() in LOTL_BINARIES:
            score += 10
            signals.append("SIG_LOTL_BENIGN_CONTEXT")
        
        # 3. Script execution
        if _is_script_execution(img, args):
            score += 70
            signals.append("SIG_SCRIPT_EXECUTION")
        
        # 4. Masquerading
        if _is_masquerading(img, path):
            score += 60
            signals.append("SIG_MASQUERADING")
        elif _is_anomalous_path(path, img):
            score += 40
            signals.append("SIG_ANOMALOUS_PATH")
        
        # 5. Network anomalies
        net_score = _score_network(data["netscan"])
        if net_score:
            score += net_score
            signals.append("SIG_SUSPICIOUS_NETWORK")
        
        # 6. Parent-child anomaly
        if _has_anomalous_parent(pid, parent_map, pid_table):
            score += 30
            signals.append("SIG_PARENT_ANOMALY")
        
        # 7. Empty command line (hollow process indicator)
        if not args and not _is_expected_empty_cmdline(img):
            score += 20
            signals.append("SIG_EMPTY_CMDLINE")
        
        # Hard cap to prevent runaway composite scores
        score = min(score, 250)
        data["score"] = score
        data["signals"] = signals
        results.append((pid, score, signals))
    
    return results

# =============================================================================
# PHASE 3: BUDGET-AWARE SELECTION
# =============================================================================

def select_suspects(scored_results: List[Tuple[int, int, List[str]]], api_budget: int = 20) -> List[int]:
    """
    Deterministic selection. Always takes critical (>=150), then fills budget
    with highest high-suspect (60-149). Returns ordered list of PIDs.
    """
    # Sort by score descending, then PID ascending for deterministic tie-breaking
    ranked = sorted(scored_results, key=lambda x: (x[1], -x[0]), reverse=True)
    
    critical = [pid for pid, score, _ in ranked if score >= 150]
    high = [pid for pid, score, _ in ranked if 60 <= score < 150]
    
    suspects = critical[:api_budget]
    remaining = api_budget - len(suspects)
    if remaining > 0:
        suspects.extend(high[:remaining])
    
    # Deduplicate while preserving rank order
    seen = set()
    final = []
    for pid in suspects:
        if pid not in seen:
            seen.add(pid)
            final.append(pid)
    return final

# =============================================================================
# ORCHESTRATOR INTEGRATION
# =============================================================================

def get_suspect_pids(api_budget: int = 20) -> Tuple[List[int], Dict[int, Any]]:
    """
    Drop-in replacement for your existing RWX-only PID selection.
    Returns: (ordered_suspect_pids, pid_table_for_reuse)
    """
    ExecutionLogger.log("ORCHESTRATOR", "SMPT Phase 1: Building multi-signal PID index...")
    pid_table, parent_map = build_pid_table()
    
    ExecutionLogger.log("ORCHESTRATOR", "SMPT Phase 2: Running deterministic scoring...")
    scored = score_pid_table(pid_table, parent_map)
    
    critical = sum(1 for _, s, _ in scored if s >= 150)
    high = sum(1 for _, s, _ in scored if 60 <= s < 150)
    low = sum(1 for _, s, _ in scored if s < 60)
    
    ExecutionLogger.log(
        "ORCHESTRATOR",
        f"SMPT complete. Total={len(scored)} | Critical={critical} | High={high} | Cleared={low}",
        "SUCCESS"
    )
    
    suspects = select_suspects(scored, api_budget=api_budget)
    ExecutionLogger.log("ORCHESTRATOR", f"SMPT Phase 3: Selected {len(suspects)} PIDs for LLM: {suspects}")
    
    return suspects, pid_table
```

---

## Integration: Replacing the RWX Myopia in `orchestrator.py`

Replace your existing PID selection block:

```python
# OLD (v0.1.8) — RWX Myopia
# pids = []
# malfind_path = os.path.join(CACHE_DIR, "malfind.json")
# if os.path.exists(malfind_path):
#     ...

# NEW (v0.1.9) — SMPT Broad-Spectrum Triage
from triage import get_suspect_pids

def run_fsm_loop(chat_session):
    ExecutionLogger.log("ORCHESTRATOR", "Initializing Exhaustive Deterministic State Machine...")
    ctx = get_evidence_context()
    
    # --- NEW: Multi-signal selection ---
    suspect_pids, pid_table = get_suspect_pids(api_budget=20)
    
    if not suspect_pids:
        ExecutionLogger.log("ORCHESTRATOR", "No high-suspect PIDs identified. Investigation Complete.", "SUCCESS")
        return
    
    ExecutionLogger.log("ORCHESTRATOR", f"Proceeding to iterate {len(suspect_pids)} suspect PIDs deterministically.")
    
    investigation_results = []
    for pid in suspect_pids:
        # ... rest of your existing evaluation loop remains unchanged ...
```

---

## Why This Fits Your Hardware Constraints

| Constraint | How SMPT Satisfies It |
|---|---|
| **1.3 GiB RAM** | The entire PID table for 150 processes is < 1 MB. No memory images are loaded in this phase. |
| **Celeron N4020 (2 cores)** | Purely sequential `for` loops over small lists. Zero threading. Zero `asyncio`. All regex compiled once at import. |
| **No SQLite / FUSE issues** | Reads your existing flat JSON caches exactly once. No DB writes, no locking. |
| **USB I/O latency** | 4 small JSON reads (~50–200 KB each). Negligible compared to 12 repeated `icat \| strings` hive carves. |
| **API cost / time** | Bounded by `api_budget`. You will never send > 20 PIDs to the LLM, regardless of host size. |

---

## What You Now Catch (That RWX Missed)

| Attack Type | Signal(s) Triggered | Example |
|---|---|---|
| **PowerShell fileless downloader** | `SIG_LOTL_SUSPICIOUS_ARGS` (+80) | `powershell -enc SQBFAFgAIAA...` |
| **MSHTA / WScript payload** | `SIG_SCRIPT_EXECUTION` (+70) | `mshta javascript:...` |
| **Rundll32 sideload from Temp** | `SIG_LOTL_SUSPICIOUS_ARGS` (+80), `SIG_ANOMALOUS_PATH` (+40) | `rundll32 C:\Users\X\AppData\Local\Temp\evil.dll,Entry` |
| **Masquerading svchost** | `SIG_MASQUERADING` (+60) | `svchost.exe` running from `C:\Users\Public\` |
| **Python ransomware / infostealer** | `SIG_SCRIPT_EXECUTION` (+70), `SIG_SUSPICIOUS_NETWORK` (+25–50) | `python.exe stealer.py` beaconing to rare IP:8080 |
| **Office macro -> cmd.exe** | `SIG_PARENT_ANOMALY` (+30), `SIG_LOTL_SUSPICIOUS_ARGS` (+80) | `WINWORD.EXE` spawning `cmd /c` |
| **Network-only RAT (no injection)** | `SIG_SUSPICIOUS_NETWORK` (+50) | Clean memory, but `ESTABLISHED` to `203.0.113.7:4444` |
| **Hollow process / no cmdline** | `SIG_EMPTY_CMDLINE` (+20), `SIG_MASQUERADING` (+60) | `explorer.exe` with null command line |

---

## Final Note on Registry Correlation

Your v0.1.8 execution log revealed that **every PID was polluted with the same global NTUSER artifacts** (`UAC.dll` in `AppData\Local\Temp`). Because SMPT selects PIDs based on process-local signals (path, parent, network, cmdline), you can **decouple registry findings from PID scoring**. Use the registry carve to generate a **host-level IOC list** ("this machine has temp-DLL persistence"), but only attribute a registry artifact to a specific PID if you can correlate it via username, loaded module path, or process-specific memory carve. This eliminates the MsMpEng.exe false positive you observed.
