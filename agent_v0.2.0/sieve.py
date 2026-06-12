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
        "winlogon.exe", "lsass.exe", "svchost.exe", "registry", "system"
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
            try:
                pstree_data = json.load(f)
            except:
                pstree_data = []
        
        def _walk(node, parent_pid=None):
            pid = node.get("PID")
            if pid is not None:
                pid = int(pid)
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
                if explicit_ppid is not None:
                    parent_map[pid] = int(explicit_ppid)
                elif parent_pid is not None:
                    parent_map[pid] = int(parent_pid)
            current = pid if pid is not None else parent_pid
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
            try:
                for entry in json.load(f):
                    pid = entry.get("PID")
                    if pid is not None and int(pid) in pid_table:
                        pid_table[int(pid)]["cmdline"] = entry
            except:
                pass
    
    # --- NETSCAN ---
    netscan_path = os.path.join(CACHE_DIR, "netscan.json")
    if os.path.exists(netscan_path):
        with open(netscan_path, "r", encoding="utf-8", errors="ignore") as f:
            try:
                for entry in json.load(f):
                    pid = entry.get("PID")
                    if pid is not None and int(pid) in pid_table:
                        pid_table[int(pid)]["netscan"].append(entry)
            except:
                pass
    
    # --- MALFIND ---
    malfind_path = os.path.join(CACHE_DIR, "malfind.json")
    if os.path.exists(malfind_path):
        with open(malfind_path, "r", encoding="utf-8", errors="ignore") as f:
            try:
                for entry in json.load(f):
                    pid = entry.get("PID")
                    if pid is not None and int(pid) in pid_table:
                        pid_table[int(pid)]["malfind"].append(entry)
            except:
                pass
    
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
