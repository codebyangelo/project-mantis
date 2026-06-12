import json
import os
import re
from typing import Dict, List, Tuple, Any
import datetime
from config import CACHE_DIR
from lnk_parser import parse_lnk_shell_items
from registry_parser import extract_usbstor_from_hive
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
TRUNCATED_SYSTEM_NAMES = ['smss.exe', 'memcompression', 'searchindexer', 'searchfilterho', 'crashpad_handl', 'runtimebroker.', 'win32bridge.se', 'adobearmhelper', 'searchprotocol']
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
    if RE_TRUNCATED_EXE.search(img) or (len(img) in (14, 15) and not img.lower().endswith('.exe')):
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
        malfind_hits = data["malfind"]
        has_rwx = any(m.get("Protection") == "PAGE_EXECUTE_READWRITE" for m in malfind_hits)
        has_jmp_rax = any("jmp rax" in str(m.get("Disasm", "")).lower() for m in malfind_hits)
        if has_rwx or has_jmp_rax:
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

# =============================================================================
# PHASE 3: ENTITY AGGREGATION & SELECTION
# =============================================================================

def get_suspect_entities(api_budget: int = 30) -> List[Dict]:
    """
    Entity-centric deterministic selection. Replaces the old PID-only get_suspect_pids.
    Returns: List of SuspectEntity dicts.
    """
    ExecutionLogger.log("ORCHESTRATOR", "SMPT Phase 1: Building multi-signal Entity index...")
    entities = []
    
    
    lnk_data = {}
    if os.path.exists(CACHE_DIR):
        for f in os.listdir(CACHE_DIR):
            if f.startswith("lnk_stream_") and f.endswith(".json"):
                with open(os.path.join(CACHE_DIR, f), "r") as lf:
                    try: lnk_data.update(json.load(lf))
                    except: pass
                    
    # --- 1. MEMORY PROCESSES ---

    pid_table, parent_map = build_pid_table()
    if pid_table:
        scored_pids = score_pid_table(pid_table, parent_map)
        for pid, score, signals in scored_pids:
            pstree = pid_table[pid].get("pstree") or {}
            cmdline = pid_table[pid].get("cmdline") or {}
            img = pstree.get("ImageFileName", "")
            args = cmdline.get("Args", "")
            
            # Reduce Truncation False Positives
            if score > 0:
                is_trunc = (img.endswith(".ex") or len(img) in (14, 15))
                is_whitelisted = any(tsn in img.lower() for tsn in TRUNCATED_SYSTEM_NAMES)
                has_args_match = args and img.replace(".ex", "").lower() in args.lower()
                
                if is_trunc and (is_whitelisted or has_args_match):
                    score = max(0, score - 60)
                    if "SIG_MASQUERADING" in signals:
                        signals.remove("SIG_MASQUERADING")
            
            pid_table[pid]["score"] = score
            entities.append({
                "type": "process",
                "id": str(pid),
                "label": f"PID {pid} ({img})",
                "score": score,
                "evidence": {
                    "signals": signals,
                    "pstree": pstree,
                    "cmdline": cmdline,
                    "netscan": pid_table[pid].get("netscan", []),
                    "malfind": pid_table[pid].get("malfind", [])
                }
            })
            
    # --- 2. DISK ARTIFACTS (BODYFILE) ---
    if os.path.exists(CACHE_DIR):
        for f in os.listdir(CACHE_DIR):
            if f.startswith("bodyfile_") and f.endswith(".txt"):
                disk_image_name = f.replace("bodyfile_", "").replace(".txt", "")
                bodyfile_path = os.path.join(CACHE_DIR, f)
                try:
                    with open(bodyfile_path, "r", encoding="utf-8", errors="ignore") as bf:
                        for line in bf:
                            parts = line.split("|")
                            if len(parts) >= 7:
                                inode = parts[2]
                                path = parts[1]
                                size = parts[6]
                                
                                p_lower = path.lower()
                                clean_path = p_lower.replace(" ($file_name)", "").replace(" (deleted)", "").strip()
                                
                                is_malware = False
                                is_leakage = False
                                
                                # Malware Drop Zones
                                if "/temp/" in clean_path or "/appdata/roaming/" in clean_path or "/users/public/" in clean_path:
                                    if clean_path.endswith((".exe", ".dll", ".bat", ".ps1")):
                                        is_malware = True
                                
                                # Data Leakage Indicators (Generic)
                                if "/users/" in clean_path and ("/desktop/" in clean_path or "/documents/" in clean_path or "/downloads/" in clean_path or "/appdata/" in clean_path):
                                    if clean_path.endswith((".docx", ".doc", ".pdf", ".xls", ".xlsx", ".lnk", ".zip", ".rar", ".7z", ".tar", ".gz")):
                                        # Flag if it's a deleted document/shortcut, or if it's an archive format (often used to stage data before exfiltration)
                                        if "(deleted)" in p_lower or clean_path.endswith((".zip", ".rar", ".7z", ".tar", ".gz")):
                                            is_leakage = True
                                        # NEW: Explicitly flag LNK files in Recent folder for USB hunting
                                        if clean_path.endswith(".lnk") and "/recent/" in p_lower:
                                            is_leakage = True

                                if is_malware or is_leakage:
                                    
                                    macb = {}
                                    try:
                                        if len(parts) >= 11:
                                            macb["accessed_time"] = datetime.datetime.utcfromtimestamp(int(parts[7])).isoformat() + "Z" if parts[7] != "0" else "Unknown"
                                            macb["modified_time"] = datetime.datetime.utcfromtimestamp(int(parts[8])).isoformat() + "Z" if parts[8] != "0" else "Unknown"
                                            macb["changed_time"]  = datetime.datetime.utcfromtimestamp(int(parts[9])).isoformat() + "Z" if parts[9] != "0" else "Unknown"
                                            macb["created_time"]  = datetime.datetime.utcfromtimestamp(int(parts[10])).isoformat() + "Z" if parts[10] != "0" else "Unknown"
                                    except Exception:
                                        macb = {"error": "Failed to parse MACB"}

                                    evidence_dict = {
                                        "signals": ["SIG_DATA_LEAKAGE_INDICATOR"] if is_leakage else ["SIG_ANOMALOUS_DISK_FILE"],
                                        "path": path,
                                        "inode": inode,
                                        "disk_image": disk_image_name,
                                        "size": size,
                                        "deleted": "(deleted)" in p_lower,
                                        "macb_timestamps": macb
                                    }
                                    name = path.split('/')[-1]
                                    if name in lnk_data:
                                        evidence_dict["lnk_carved_strings"] = lnk_data[name]

                                    score = 100 if is_leakage else 80
                                    
                                    if clean_path.endswith(".zip") or clean_path.endswith(".rar"):
                                        # Archive Content Extraction
                                        real_disk_path = ""
                                        ctx_path = os.path.join(CACHE_DIR, "context.json")
                                        if os.path.exists(ctx_path):
                                            try:
                                                with open(ctx_path) as ctxf:
                                                    for p in json.load(ctxf).get("Evidence_Files", {}).get("Disk_Images", []):
                                                        if disk_image_name in p:
                                                            real_disk_path = p
                                                            break
                                            except: pass
                                        if real_disk_path:
                                            temp_arc = f"/tmp/arc_{inode}"
                                            import subprocess
                                            import hashlib
                                            import zipfile
                                            try:
                                                from lnk_parser import get_partition_offset
                                                offset = get_partition_offset(real_disk_path)
                                                img_type = "ewf" if real_disk_path.lower().endswith(".e01") else "raw"
                                                icat_cmd = ["icat", "-i", img_type]
                                                if offset: icat_cmd.extend(["-o", offset])
                                                icat_cmd.extend([real_disk_path, str(inode).split('-')[0]])
                                                subprocess.run(icat_cmd, stdout=open(temp_arc, 'wb'))
                                                
                                                if zipfile.is_zipfile(temp_arc):
                                                    with zipfile.ZipFile(temp_arc, 'r') as z:
                                                        namelist = z.namelist()
                                                        if namelist:
                                                            first_file = namelist[0]
                                                            with z.open(first_file) as fz:
                                                                content_bytes = fz.read()
                                                                file_hash = hashlib.md5(content_bytes).hexdigest()
                                                                evidence_dict["archive_inspection"] = {
                                                                    "first_file": first_file,
                                                                    "md5": file_hash,
                                                                    "is_exe": first_file.lower().endswith(".exe"),
                                                                    "is_sdelete": "sdelete" in first_file.lower()
                                                                }
                                                                if "sdelete" in first_file.lower() or "wipe" in first_file.lower():
                                                                    evidence_dict["signals"].append("SIG_ANTI_FORENSICS_INDICATOR")
                                                                    if "SIG_DATA_LEAKAGE_INDICATOR" in evidence_dict["signals"]:
                                                                        evidence_dict["signals"].remove("SIG_DATA_LEAKAGE_INDICATOR")
                                            except Exception as e:
                                                evidence_dict["archive_error"] = str(e)
                                            if os.path.exists(temp_arc): os.remove(temp_arc)
                                            
                                    if clean_path.endswith(".lnk"):
                                        # Deterministic LNK Parsing
                                        real_disk_path = ""
                                        ctx_path = os.path.join(CACHE_DIR, "context.json")
                                        if os.path.exists(ctx_path):
                                            try:
                                                with open(ctx_path) as ctxf:
                                                    for p in json.load(ctxf).get("Evidence_Files", {}).get("Disk_Images", []):
                                                        if disk_image_name in p:
                                                            real_disk_path = p
                                                            break
                                            except: pass
                                            
                                        if real_disk_path:
                                            lnk_target = parse_lnk_shell_items(inode, real_disk_path)
                                            if lnk_target:
                                                evidence_dict.update(lnk_target)
                                                tag = lnk_target.get("lnk_baseline_tag", "PATH_BASELINE_UNKNOWN")
                                                if tag.startswith("PATH_BASELINE_LOCAL:templates"):
                                                    score = 0
                                                elif tag.startswith("PATH_BASELINE_LOCAL") or tag.startswith("NET_BASELINE_CORPORATE"):
                                                    score = 50
                                                elif tag.startswith("PATH_BASELINE_REMOVABLE"):
                                                    score = 90 # Pending USB correlation -> Critical
                                                elif tag.startswith("PATH_BASELINE_PARSE_ERROR"):
                                                    score = 50 # Failed parse is not evidence of malice
                                                else:
                                                    score = 90 # PATH_BASELINE_UNKNOWN -> Medium
                                                if is_leakage and score != 0: score = max(score, 100)
                                    
                                    entities.append({
                                        "type": "file",
                                        "id": inode,
                                        "label": path,
                                        "score": score,
                                        "evidence": evidence_dict
                                    })
                except Exception:
                    pass

    # --- 3. REGISTRY HIVES ---
    if os.path.exists(CACHE_DIR):
        for f in os.listdir(CACHE_DIR):
            if f.startswith("registry_map_") and f.endswith(".json"):
                disk_image_name = f.replace("registry_map_", "").replace(".json", "")
                reg_path = os.path.join(CACHE_DIR, f)
                try:
                    with open(reg_path, "r") as rfile:
                        reg_map = json.load(rfile)
                        for hive_type, val in reg_map.items():
                            if hive_type in ("SYSTEM", "SOFTWARE"):
                                # Extractor generates lists of dicts for SYSTEM and SOFTWARE too
                                if isinstance(val, list):
                                    for entry in val:
                                        score = 90
                                        ev_dict = {
                                            "signals": ["SIG_REGISTRY_PERSISTENCE_CHECK"],
                                            "hive_type": hive_type,
                                            "inode": str(entry.get("inode")),
                                            "disk_image": disk_image_name
                                        }
                                        if hive_type == "SYSTEM":
                                            real_disk_path = ""
                                            ctx_path = os.path.join(CACHE_DIR, "context.json")
                                            if os.path.exists(ctx_path):
                                                try:
                                                    with open(ctx_path) as ctxf:
                                                        for p in json.load(ctxf).get("Evidence_Files", {}).get("Disk_Images", []):
                                                            if disk_image_name in p:
                                                                real_disk_path = p
                                                                break
                                                except: pass
                                            if real_disk_path:
                                                temp_hive = f"/tmp/hive_{str(entry.get('inode')).split('-')[0]}"
                                                import subprocess
                                                img_type = "ewf" if real_disk_path.lower().endswith(".e01") else "raw"
                                                subprocess.run(["icat", "-i", img_type, real_disk_path, str(entry.get('inode')).split('-')[0]], stdout=open(temp_hive, 'wb'))
                                                usbstor = extract_usbstor_from_hive(temp_hive)
                                                if os.path.exists(temp_hive): os.remove(temp_hive)
                                                if usbstor:
                                                    ev_dict["usbstor_keys"] = usbstor
                                                    # Cross-correlate LNKs
                                                    for e in entities:
                                                        if e["type"] == "file" and e["evidence"].get("lnk_is_removable"):
                                                            e["score"] = 99 # Critical
                                                else:
                                                    score = 50 # No keys -> Low
                                        
                                        entities.append({
                                            "type": "registry_hive",
                                            "id": str(entry.get("inode")),
                                            "label": f"{hive_type} Hive",
                                            "score": score,
                                            "evidence": ev_dict
                                        })
                                else:
                                    entities.append({
                                        "type": "registry_hive",
                                        "id": str(val.get("inode") if isinstance(val, dict) else val),
                                        "label": f"{hive_type} Hive",
                                        "score": 90, # Base score to ensure inspection
                                        "evidence": {
                                            "signals": ["SIG_REGISTRY_PERSISTENCE_CHECK"],
                                            "hive_type": hive_type,
                                            "inode": str(val.get("inode") if isinstance(val, dict) else val),
                                            "disk_image": disk_image_name
                                        }
                                    })
                            elif hive_type == "NTUSER" and isinstance(val, list):
                                for user_entry in val:
                                    entities.append({
                                        "type": "registry_hive",
                                        "id": str(user_entry.get("inode")),
                                        "label": f"NTUSER Hive ({user_entry.get('path')})",
                                        "score": 90,
                                        "evidence": {
                                            "signals": ["SIG_REGISTRY_PERSISTENCE_CHECK"],
                                            "hive_type": "NTUSER",
                                            "inode": str(user_entry.get("inode")),
                                            "path": user_entry.get("path"),
                                            "disk_image": disk_image_name
                                        }
                                    })
                except Exception:
                    pass

    # --- 4. DEEP FORENSICS: EVTX ---
    if os.path.exists(CACHE_DIR):
        for f in os.listdir(CACHE_DIR):
            if f.startswith("evtx_stream_") and f.endswith(".json"):
                disk_image_name = f.replace("evtx_stream_", "").replace(".json", "")
                evtx_path = os.path.join(CACHE_DIR, f)
                try:
                    with open(evtx_path, "r") as evfile:
                        evtx_data = json.load(evfile)
                        for evtx_name, hits in evtx_data.items():
                            entities.append({
                                "type": "event_log",
                                "id": f"evtx_{disk_image_name}_{evtx_name}",
                                "label": f"EVTX {evtx_name}",
                                "score": 95,
                                "evidence": {
                                    "signals": ["SIG_EVTX_SUSPICIOUS_STRING"],
                                    "log_file": evtx_name,
                                    "disk_image": disk_image_name,
                                    "hits": hits[:50] # Limit hits to prevent token explosion
                                }
                            })
                except Exception:
                    pass

    # --- 5. DEEP FORENSICS: PREFETCH ---
    if os.path.exists(CACHE_DIR):
        for f in os.listdir(CACHE_DIR):
            if f.startswith("prefetch_stream_") and f.endswith(".json"):
                disk_image_name = f.replace("prefetch_stream_", "").replace(".json", "")
                pf_path = os.path.join(CACHE_DIR, f)
                try:
                    with open(pf_path, "r") as pffile:
                        pf_data = json.load(pffile)
                        for pf_name, hits in pf_data.items():
                            entities.append({
                                "type": "prefetch_artifact",
                                "id": f"pf_{disk_image_name}_{pf_name}",
                                "label": f"Prefetch {pf_name}",
                                "score": 85,
                                "evidence": {
                                    "signals": ["SIG_PREFETCH_SUSPICIOUS_EXECUTION"],
                                    "prefetch_file": pf_name,
                                    "disk_image": disk_image_name,
                                    "hits": hits[:50] # Limit hits
                                }
                            })
                except Exception:
                    pass

    # --- 6. DEEP FORENSICS: PCAP ---
    if os.path.exists(CACHE_DIR):
        for f in os.listdir(CACHE_DIR):
            if f.startswith("pcap_stream_") and f.endswith(".json"):
                pcap_name_base = f.replace("pcap_stream_", "").replace(".json", "")
                pcap_path = os.path.join(CACHE_DIR, f)
                try:
                    with open(pcap_path, "r") as pffile:
                        pcap_data = json.load(pffile)
                        for pcap_name, hits in pcap_data.items():
                            entities.append({
                                "type": "network_capture",
                                "id": f"pcap_{pcap_name_base}",
                                "label": f"PCAP {pcap_name}",
                                "score": 90,
                                "evidence": {
                                    "signals": ["SIG_PCAP_SUSPICIOUS_STRING"],
                                    "pcap_file": pcap_name,
                                    "hits": hits[:50] # Limit hits
                                }
                            })
                except Exception:
                    pass

    # --- FILTER AND SORT ---
    ExecutionLogger.log("ORCHESTRATOR", "SMPT Phase 2: Running deterministic scoring...")
    entities.sort(key=lambda x: x["score"], reverse=True)
    
    seen = set()
    final_entities = []
    
    critical = 0
    high = 0
    low = 0
    
    type_counts = {}
    type_limits = {
        "file": 10,
        "process": 15,
        "registry_hive": 5,
        "network_capture": 5,
        "prefetch": 5
    }
    
    for ent in entities:
        if ent["score"] >= 150: critical += 1
        elif ent["score"] >= 60: high += 1
        else: low += 1
        
        if ent["score"] < 60:
            continue
            
        t = ent["type"]
        if t == "file":
            clean_path = ent["evidence"].get("path", ent["id"]).replace(" ($FILE_NAME)", "")
            ent_key = ("file", clean_path)
        else:
            ent_key = (ent["type"], ent["id"])
            
        if ent_key not in seen:
            if type_counts.get(t, 0) < type_limits.get(t, 10):
                seen.add(ent_key)
                type_counts[t] = type_counts.get(t, 0) + 1
                final_entities.append(ent)
                
            if len(final_entities) >= api_budget:
                break
                
    ExecutionLogger.log(
        "ORCHESTRATOR",
        f"SMPT complete. Total={len(entities)} | Critical={critical} | High={high} | Cleared={low}",
        "SUCCESS"
    )
    ExecutionLogger.log("ORCHESTRATOR", f"SMPT Phase 3: Selected {len(final_entities)} Entities for LLM.")
    
    return final_entities
