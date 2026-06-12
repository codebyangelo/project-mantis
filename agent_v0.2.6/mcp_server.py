import subprocess
import os
import json
import time
import sys
import threading
import hashlib
import re
from typing import List, Tuple, Set
from config import EVIDENCE_DIR, CACHE_DIR, PLAYBOOK_PATH
from logger import ExecutionLogger

def validate_path(path_str: str) -> str:
    """Validates and resolves a path against allowed sandbox directories to prevent traversal."""
    ExecutionLogger.log("MCP_SERVER", f"Validating path security for: {path_str}")
    if not isinstance(path_str, str) or "\x00" in path_str:
        ExecutionLogger.log("MCP_SERVER", "Validation failed: Null bytes or invalid format.", "ERROR")
        raise ValueError("Invalid path format.")
    
    real_p = os.path.realpath(path_str)
    allowed = [os.path.realpath(EVIDENCE_DIR), os.path.realpath(CACHE_DIR)]
    
    is_allowed = False
    for a in allowed:
        try:
            if os.path.commonpath([a, real_p]) == a:
                is_allowed = True
                break
        except ValueError:
            pass
            
    if not is_allowed:
        ExecutionLogger.log("MCP_SERVER", f"Path traversal blocked: {path_str}", "ERROR")
        raise ValueError(f"Path traversal attempt blocked: {path_str}")
    
    ExecutionLogger.log("MCP_SERVER", f"Path validated securely: {real_p}", "SUCCESS")
    return real_p

def run_with_timer(cmd: list, task_name: str, timeout_sec: int = 300) -> str:
    """Executes a synchronous blocking subprocess without threading."""
    ExecutionLogger.log("MCP_SERVER", f"Starting synchronous subprocess for: {task_name}")
    ExecutionLogger.log("MCP_SERVER", f"Command vector: {cmd}")
    ExecutionLogger.log("MCP_SERVER", f"[*] Tool running... (Timeout: {timeout_sec}s)")
    
    try:
        start_time = time.time()
        result = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=timeout_sec)
        elapsed = time.time() - start_time
        
        if result.returncode != 0:
            ExecutionLogger.log("MCP_SERVER", f"Subprocess failed (exit {result.returncode}): {result.stderr.strip()}", "ERROR")
            return result.stdout if result.stdout else ""
            
        ExecutionLogger.log("MCP_SERVER", f"Task completed in {elapsed:.2f}s: {task_name}", "SUCCESS")
        return result.stdout
    except subprocess.TimeoutExpired:
        ExecutionLogger.log("MCP_SERVER", f"Command timed out after {timeout_sec}s.", "ERROR")
        raise Exception(f"Command timed out after {timeout_sec}s")
    except Exception as e:
        ExecutionLogger.log("MCP_SERVER", f"Subprocess Error: {e}", "ERROR")
        raise Exception(str(e))

def get_evidence_context() -> str:
    ExecutionLogger.log("MCP_SERVER", "Executing get_evidence_context()")
    path = os.path.join(CACHE_DIR, "context.json")
    if os.path.exists(path):
        ExecutionLogger.log("MCP_SERVER", "Context cache found.")
        with open(path, "r") as f:
            return f.read()
    ExecutionLogger.log("MCP_SERVER", "Context cache not found.", "WARN")
    return '{"MODE": "UNKNOWN", "ERROR": "Context not built. Run extractor."}'

def resolve_username_from_pid(pid: str) -> str:
    ExecutionLogger.log("MCP_SERVER", f"Resolving username for PID {pid}...")
    cmdline_path = os.path.join(CACHE_DIR, "cmdline.json")
    if os.path.exists(cmdline_path):
        try:
            with open(cmdline_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
                for entry in data:
                    if str(entry.get("PID")) == str(pid):
                        args = entry.get("Args") or ""
                        match = re.search(r"[uU]sers[\\/]([^\\/]+)", args)
                        if match:
                            user = match.group(1)
                            ExecutionLogger.log("MCP_SERVER", f"Username '{user}' resolved from cmdline.")
                            return user
        except Exception as e:
            ExecutionLogger.log("MCP_SERVER", f"Failed to parse cmdline.json: {e}", "WARN")
            
    pstree_path = os.path.join(CACHE_DIR, "pstree.json")
    if os.path.exists(pstree_path):
        try:
            with open(pstree_path, "r", encoding="utf-8", errors="ignore") as f:
                pstree = json.load(f)
                
            def find_user_in_tree(node):
                if str(node.get("PID")) == str(pid):
                    path = node.get("Path") or ""
                    match = re.search(r"[uU]sers[\\/]([^\\/]+)", path)
                    if match:
                        return match.group(1)
                for child in node.get("__children", []):
                    u = find_user_in_tree(child)
                    if u: return u
                return None

            if isinstance(pstree, list):
                for n in pstree:
                    u = find_user_in_tree(n)
                    if u:
                        ExecutionLogger.log("MCP_SERVER", f"Username '{u}' resolved from pstree.")
                        return u
            else:
                u = find_user_in_tree(pstree)
                if u:
                    ExecutionLogger.log("MCP_SERVER", f"Username '{u}' resolved from pstree.")
                    return u
        except Exception as e:
            ExecutionLogger.log("MCP_SERVER", f"Failed to parse pstree.json: {e}", "WARN")
            
    ExecutionLogger.log("MCP_SERVER", f"Username for PID {pid} could not be resolved.")
    return ""

def query_json_cache(cache_name: str, keyword: str = "") -> str:
    ExecutionLogger.log("MCP_SERVER", f"Executing query_json_cache(cache='{cache_name}', keyword='{keyword}')")
    
    if not re.match(r"^[a-zA-Z0-9_]+$", cache_name):
        ExecutionLogger.log("MCP_SERVER", "Invalid cache name format.", "ERROR")
        return "[!] Invalid cache name."
        
    keyword_str = str(keyword).strip()
    if cache_name == "registry_map" and keyword_str.isdigit():
        ExecutionLogger.log("MCP_SERVER", f"Special handler triggered: Registry Map redirect for PID {keyword_str}")
        user = resolve_username_from_pid(keyword_str)
        reg_map_path = os.path.join(CACHE_DIR, "registry_map.json")
        if os.path.exists(reg_map_path):
            try:
                with open(reg_map_path, "r", encoding="utf-8", errors="ignore") as f:
                    reg_map = json.load(f)
                result_dict = {}
                if "SYSTEM" in reg_map:
                    result_dict["SYSTEM"] = reg_map["SYSTEM"]
                if "SOFTWARE" in reg_map:
                    result_dict["SOFTWARE"] = reg_map["SOFTWARE"]
                if user and "NTUSER" in reg_map:
                    user_ntuser = [e for e in reg_map["NTUSER"] if f"/{user}/" in e.get("path", "").replace("\\", "/").lower()]
                    result_dict["NTUSER"] = user_ntuser if user_ntuser else reg_map["NTUSER"]
                elif "NTUSER" in reg_map:
                    result_dict["NTUSER"] = reg_map["NTUSER"]
                ExecutionLogger.log("MCP_SERVER", f"Registry Map Query successfully redirected and filtered.", "SUCCESS")
                return json.dumps(result_dict, indent=2)
            except Exception as e:
                ExecutionLogger.log("MCP_SERVER", f"Registry redirect failed: {e}", "ERROR")

    try:
        filepath = validate_path(os.path.join(CACHE_DIR, f"{cache_name}.json"))
    except Exception as e:
        return f"[!] {e}"

    if not os.path.exists(filepath):
        ExecutionLogger.log("MCP_SERVER", f"Cache file not found: {filepath}", "WARN")
        return f"[!] Cache for {cache_name} not found."

    try:
        ExecutionLogger.log("MCP_SERVER", f"Reading cache file: {filepath}")
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            raw_content = f.read()

        if cache_name == "malfind" and keyword == "PAGE_EXECUTE_READWRITE":
            try:
                data = json.loads(raw_content)
                pids = list({str(entry.get("PID")) for entry in data if entry.get("Protection") == "PAGE_EXECUTE_READWRITE"})
                if not pids:
                    ExecutionLogger.log("MCP_SERVER", "No PAGE_EXECUTE_READWRITE segments found.")
                    return "[*] No PAGE_EXECUTE_READWRITE segments found."
                ExecutionLogger.log("MCP_SERVER", f"Identified RWX PIDs: {pids}")
                return f"[*] Identified PIDs with PAGE_EXECUTE_READWRITE segments: {', '.join(pids)}"
            except Exception as e:
                ExecutionLogger.log("MCP_SERVER", f"Failed to parse malfind data: {e}", "WARN")

        if not keyword:
            if len(raw_content) > 50000:
                ExecutionLogger.log("MCP_SERVER", "Payload too large without keyword filtering.", "WARN")
                return f"[!] Payload too large. Use a keyword."
            return raw_content

        try:
            data = json.loads(raw_content)
            if isinstance(data, list):
                keyword_str = str(keyword).lower()
                filtered = [e for e in data if isinstance(e, dict) and any(keyword_str in str(k).lower() or keyword_str in str(v).lower() for k, v in e.items())]
                if filtered:
                    ExecutionLogger.log("MCP_SERVER", f"Found {len(filtered)} matching objects in JSON list.", "SUCCESS")
                    out = json.dumps(filtered, indent=2)
                    return out[:8000] + "\n\n[!] OUTPUT TRUNCATED" if len(out) > 8000 else out
                return f"[*] Keyword '{keyword}' not found."
            elif isinstance(data, dict):
                keyword_str = str(keyword).lower()
                filtered = {k: v for k, v in data.items() if keyword_str in str(k).lower() or keyword_str in str(v).lower()}
                if filtered:
                    ExecutionLogger.log("MCP_SERVER", f"Found matching objects in JSON dict.", "SUCCESS")
                    return json.dumps(filtered, indent=2)
        except json.JSONDecodeError:
            ExecutionLogger.log("MCP_SERVER", "File is not JSON, falling back to text search.")
            pass

        matched = [line.strip() for line in raw_content.splitlines() if keyword.lower() in line.lower()]
        if not matched:
            ExecutionLogger.log("MCP_SERVER", f"Keyword '{keyword}' not found in text.")
            return f"[*] Keyword '{keyword}' not found."
        
        ExecutionLogger.log("MCP_SERVER", f"Found {len(matched)} matching lines.", "SUCCESS")
        res = "\n".join(matched)
        return res[:8000] + "\n\n[!] OUTPUT TRUNCATED" if len(res) > 8000 else res

    except Exception as e:
        ExecutionLogger.log("MCP_SERVER", f"Error parsing cache: {e}", "ERROR")
        return f"[!] Error parsing cache: {e}"

def extract_and_carve_hive(inode: str, disk_image_path: str) -> str:
    ExecutionLogger.log("MCP_SERVER", f"Starting Physical Hive Extraction (Inode: {inode})")
    
    if not re.fullmatch(r"[\d\-]+", str(inode)):
        ExecutionLogger.log("MCP_SERVER", "Invalid inode format.", "ERROR")
        return "[!] FATAL: Invalid inode format."
        
    try:
        disk_image_path = validate_path(disk_image_path)
    except Exception as e:
        return f"[!] Path validation failed: {e}"

    if not os.path.exists(disk_image_path):
        ExecutionLogger.log("MCP_SERVER", "Disk image not found.", "ERROR")
        return "[!] Disk image not found."

    try:
        icat_cmd = ["icat", "-i", "ewf", disk_image_path, inode]
        strings_cmd = ["strings", "-el"]
        
        ExecutionLogger.log("MCP_SERVER", f"Executing pipeline: icat {inode} | strings -el")
        icat_proc = subprocess.Popen(icat_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        strings_proc = subprocess.Popen(strings_cmd, stdin=icat_proc.stdout, stdout=subprocess.PIPE, text=True)
        icat_proc.stdout.close()
        
        output, err = strings_proc.communicate(timeout=120)
        
        if strings_proc.returncode != 0:
            ExecutionLogger.log("MCP_SERVER", f"Strings pipeline failed: {err.strip()}", "ERROR")
            return f"[!] Strings pipeline failed: {err.strip()}"
            
        exclusions = ['system32', 'syswow64', 'winsxs', 'program files', 'microsoft.net']
        results = set()
        for line in output.splitlines():
            line_lower = line.lower()
            # 1. Malware Persistence (Anomalous DLLs)
            if 'c:\\' in line_lower and '.dll' in line_lower:
                if not any(excl in line_lower for excl in exclusions):
                    results.add(line.strip())
            
            # 2. Data Leakage (USB Drive usage or sensitive documents)
            if re.search(r'\b[d-z]:\\[^\\]+', line_lower) or any(ext in line_lower for ext in ['.pdf', '.xls', '.xlsx', '.doc', '.docx', '.csv']):
                if not any(excl in line_lower for excl in ['microsoft', 'windows', 'appdata']):
                    if len(line.strip()) < 150: # Avoid massive garbage strings
                        results.add(line.strip())
        
        if not results:
            ExecutionLogger.log("MCP_SERVER", "Hive carve clean.", "SUCCESS")
            return "[*] HIVE CARVE CLEAN: No anomalous DLLs or Data Leakage indicators found."
        
        ExecutionLogger.log("MCP_SERVER", f"Anomaly detected! {len(results)} suspicious DLL paths found.", "WARN")
        return "[!] ANOMALY DETECTED IN HIVE:\n" + "\n".join(sorted(results))
    except subprocess.TimeoutExpired:
        ExecutionLogger.log("MCP_SERVER", "Forensic carve timed out after 120s.", "ERROR")
        icat_proc.kill()
        strings_proc.kill()
        return "[!] ERROR: Forensic carve timed out after 120s."
    except Exception as e:
        ExecutionLogger.log("MCP_SERVER", f"Hive carve error: {e}", "ERROR")
        return f"[!] HIVE CARVE ERROR: {e}"

class SurgicalCarver:
    """
    Targeted memory string extraction using malfind VADs + memmap metadata.
    Zero intermediate disk writes. Context-Bleed-proof.
    """
    STRINGS_RE = re.compile(rb'[ -~]{8,}')

    def __init__(self, memory_image_path: str, cache_dir: str):
        self.memory_image_path = memory_image_path
        self.cache_dir = cache_dir
        self.malfind_cache = self._load_json_cache("malfind")

    def _load_json_cache(self, name: str) -> List[dict]:
        path = os.path.join(self.cache_dir, f"{name}.json")
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []

    def _run_memmap_meta(self, pid: int, timeout: int = 120) -> List[dict]:
        """Runs 'windows.memmap' WITHOUT --dump. Returns only metadata."""
        cmd = [
            "vol", "-f", self.memory_image_path, "-r", "json",
            "windows.memmap", "--pid", str(pid)
        ]
        try:
            ExecutionLogger.log("MCP_SERVER", f"Running fast memmap metadata pass for PID {pid}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if result.returncode != 0 or not result.stdout.strip():
                return []
            return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            return []

    def _get_suspicious_vads(self, pid: int) -> List[Tuple[int, int]]:
        vads = []
        for entry in self.malfind_cache:
            if str(entry.get("PID")) != str(pid):
                continue
            prot = entry.get("Protection", "")
            if "EXECUTE_READWRITE" in prot or "WRITE_COPY" in prot or "READWRITE" in prot:
                start = entry.get("Start") or entry.get("Start VPN") or entry.get("start")
                end = entry.get("End") or entry.get("End VPN") or entry.get("end")
                if start is not None and end is not None:
                    try:
                        vads.append((int(str(start), 0), int(str(end), 0)))
                    except (ValueError, TypeError):
                        continue
        return vads

    @staticmethod
    def _coalesce_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        if not ranges:
            return []
        ranges = sorted(ranges, key=lambda x: x[0])
        merged = [list(ranges[0])]
        for off, size in ranges[1:]:
            last_off, last_size = merged[-1]
            if off <= last_off + last_size:
                new_end = max(last_off + last_size, off + size)
                merged[-1][1] = new_end - last_off
            else:
                merged.append([off, size])
        return [(int(o), int(s)) for o, s in merged]

    def carve_pid(self, pid: int, ioc_regex: re.Pattern, max_matches: int = 100) -> str:
        vads = self._get_suspicious_vads(pid)
        if not vads:
            ExecutionLogger.log("MCP_SERVER", f"No suspicious VADs found for PID {pid}. Trying network fallback.")
            return self.carve_pid_committed_fallback(pid, ioc_regex, max_matches)

        memmap = self._run_memmap_meta(pid)
        targets: List[Tuple[int, int]] = []
        for page in memmap:
            virt = page.get("Virtual")
            if virt is None:
                continue
            try:
                virt_addr = int(str(virt), 0)
            except (ValueError, TypeError):
                continue
            for start, end in vads:
                if start <= virt_addr < end:
                    off = page.get("Offset")
                    size = page.get("Size")
                    if off is not None and size is not None:
                        try:
                            targets.append((int(str(off), 0), int(str(size))))
                        except (ValueError, TypeError):
                            pass
                    break

        if not targets:
            return "[*] NULL HYPOTHESIS: Suspicious VADs are not resident or lack physical backing."

        targets = self._coalesce_ranges(targets)
        matches: Set[str] = set()
        total_scanned = 0

        with open(self.memory_image_path, "rb") as f:
            for off, size in targets:
                f.seek(off)
                remaining = size
                chunk_size = 262144
                while remaining > 0:
                    to_read = min(chunk_size, remaining)
                    chunk = f.read(to_read)
                    if not chunk:
                        break
                    total_scanned += len(chunk)
                    for raw_string in self.STRINGS_RE.findall(chunk):
                        decoded = raw_string.decode("ascii", errors="ignore")
                        if ioc_regex.search(decoded):
                            matches.add(decoded)
                            if len(matches) >= max_matches:
                                break
                    remaining -= len(chunk)
                    if len(matches) >= max_matches:
                        break

        if not matches:
            return "[*] NULL HYPOTHESIS: No IOC strings found in suspicious VAD pages."

        report = "\n".join(sorted(matches))
        return f"[*] SURGICAL CARVE COMPLETE (scanned {total_scanned} bytes):\n{report}"

    def carve_pid_committed_fallback(self, pid: int, ioc_regex: re.Pattern, max_matches: int = 100) -> str:
        memmap = self._run_memmap_meta(pid)
        targets = []
        for page in memmap:
            off = page.get("Offset")
            size = page.get("Size")
            if off is not None and size is not None:
                try:
                    targets.append((int(str(off), 0), int(str(size))))
                except (ValueError, TypeError):
                    continue
        
        targets = self._coalesce_ranges(targets)
        total_budget = 50 * 1024 * 1024
        scanned = 0
        matches = set()
        
        with open(self.memory_image_path, "rb") as f:
            for off, size in targets:
                if scanned >= total_budget:
                    break
                to_read = min(size, total_budget - scanned)
                f.seek(off)
                chunk_size = 262144
                remaining = to_read
                while remaining > 0:
                    read_len = min(chunk_size, remaining)
                    chunk = f.read(read_len)
                    if not chunk:
                        break
                    scanned += len(chunk)
                    for raw_string in self.STRINGS_RE.findall(chunk):
                        decoded = raw_string.decode("ascii", errors="ignore")
                        if ioc_regex.search(decoded):
                            matches.add(decoded)
                            if len(matches) >= max_matches:
                                break
                    remaining -= len(chunk)
                    if len(matches) >= max_matches:
                        break

        if not matches:
            return "[*] NULL HYPOTHESIS: No IOC strings found in committed memory fallback."

        report = "\n".join(sorted(matches))
        return f"[*] SURGICAL FALLBACK CARVE COMPLETE (scanned {scanned} bytes):\n{report}"

def carve_memory_strings(regex_pattern: str, memory_image_path: str, pid: str = "NONE") -> str:
    ExecutionLogger.log("MCP_SERVER", f"Starting surgical string carving for regex '{regex_pattern}' on PID {pid}")
    pid_str = str(pid).strip()
    if not pid_str.isdigit():
        return "[!] FATAL: Surgical carving requires a numeric PID."

    if regex_pattern == "NETWORK" or "http" in regex_pattern.lower():
        ioc_re = re.compile(
            r'(https?://|[a-zA-Z0-9.-]+\.(?:org|cn|biz|net|com|xyz|info)|'
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)',
            re.IGNORECASE
        )
    else:
        try:
            ioc_re = re.compile(regex_pattern, re.IGNORECASE)
        except re.error:
            return "[!] Invalid Regex Pattern"

    carver = SurgicalCarver(memory_image_path, CACHE_DIR)
    return carver.carve_pid(int(pid_str), ioc_re, max_matches=100)

def read_dfir_playbook() -> str:
    ExecutionLogger.log("MCP_SERVER", "Reading DFIR playbook.")
    if os.path.exists(PLAYBOOK_PATH):
        with open(PLAYBOOK_PATH, "r", encoding="utf-8") as f:
            return f.read()
    ExecutionLogger.log("MCP_SERVER", "Playbook not found.", "WARN")
    return "Playbook not found."
