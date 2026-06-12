import subprocess
import os
import json
import time
import sys
import threading
import hashlib
import re
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
    
    if not any(real_p.startswith(a) for a in allowed):
        ExecutionLogger.log("MCP_SERVER", f"Path traversal blocked: {path_str}", "ERROR")
        raise ValueError(f"Path traversal attempt blocked: {path_str}")
    
    ExecutionLogger.log("MCP_SERVER", f"Path validated securely: {real_p}", "SUCCESS")
    return real_p

def run_with_timer(cmd: list, task_name: str, timeout_sec: int = 120) -> str:
    """Executes a blocking subprocess without shell=True, enforcing a timeout."""
    ExecutionLogger.log("MCP_SERVER", f"Starting subprocess for: {task_name}")
    ExecutionLogger.log("MCP_SERVER", f"Command vector: {cmd}")
    
    process_state = {"is_running": True, "output": "", "error": None}
    
    def target():
        try:
            result = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=timeout_sec)
            if result.returncode != 0:
                if result.stdout:
                    process_state["output"] = result.stdout
                else:
                    process_state["error"] = Exception(f"Command failed (exit {result.returncode}): {result.stderr.strip()}")
            else:
                process_state["output"] = result.stdout
        except subprocess.TimeoutExpired:
            process_state["error"] = Exception(f"Command timed out after {timeout_sec}s")
        except Exception as e:
            process_state["error"] = e
        finally:
            process_state["is_running"] = False

    worker = threading.Thread(target=target)
    worker.start()

    start_time = time.time()
    last_update = 0.0
    try:
        while process_state["is_running"]:
            now = time.time()
            if now - last_update >= 1.0:
                elapsed = int(now - start_time)
                mins, secs = divmod(elapsed, 60)
                timer_display = f"[*] Execution Time: [{mins:02d}:{secs:02d}]"
                sys.stdout.write('\r' + timer_display)
                sys.stdout.flush()
                last_update = now
            time.sleep(0.05)
            
    except KeyboardInterrupt:
        ExecutionLogger.log("MCP_SERVER", "Timer interrupted by user.", "WARN")
        pass
        
    worker.join()
    sys.stdout.write('\n')
    ExecutionLogger.log("MCP_SERVER", f"Task completed: {task_name}", "SUCCESS")
    
    if process_state["error"]:
        ExecutionLogger.log("MCP_SERVER", f"Subprocess Error: {process_state['error']}", "ERROR")
        raise Exception(str(process_state["error"]))
        
    return process_state["output"]

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
            if 'c:\\' in line_lower and '.dll' in line_lower:
                if not any(excl in line_lower for excl in exclusions):
                    results.add(line.strip())
        
        if not results:
            ExecutionLogger.log("MCP_SERVER", "Hive carve clean.", "SUCCESS")
            return "[*] HIVE CARVE CLEAN: No anomalous absolute DLL paths found."
        
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

def carve_memory_strings(regex_pattern: str, memory_image_path: str, pid: str = "NONE") -> str:
    ExecutionLogger.log("MCP_SERVER", f"Starting memory string carving for regex '{regex_pattern}' on PID {pid}")
    pid_str = str(pid).strip()
    target_image = memory_image_path
    
    if pid_str.isdigit():
        ExecutionLogger.log("MCP_SERVER", "Locating process memory dump...")
        loose_path = os.path.join(EVIDENCE_DIR, "loose_data", f"pid.{pid_str}.dmp")
        cache_path = os.path.join(CACHE_DIR, f"pid.{pid_str}.dmp")
        if os.path.exists(loose_path):
            target_image = loose_path
            ExecutionLogger.log("MCP_SERVER", f"Using existing loose data dump: {loose_path}")
        elif os.path.exists(cache_path):
            target_image = cache_path
            ExecutionLogger.log("MCP_SERVER", f"Using existing cached dump: {cache_path}")
        else:
            has_network = False
            netscan_path = os.path.join(CACHE_DIR, "netscan.json")
            if os.path.exists(netscan_path):
                try:
                    with open(netscan_path, "r", encoding="utf-8") as f:
                        for entry in json.load(f):
                            if str(entry.get("PID")) == pid_str and entry.get("ForeignAddr") not in ["*", "0.0.0.0", "::"]:
                                has_network = True
                                break
                except Exception:
                    pass
            
            if not has_network:
                ExecutionLogger.log("MCP_SERVER", "Skipping carve: PID has no active network connections.", "INFO")
                return "[*] NULL HYPOTHESIS: Skipping memory carve (no network)."

            vol_cmd = ["vol", "-o", CACHE_DIR, "-f", memory_image_path, "windows.memmap", "--pid", pid_str, "--dump"]
            try:
                ExecutionLogger.log("MCP_SERVER", f"Dumping memory via Volatility: {vol_cmd}")
                run_with_timer(vol_cmd, f"Dumping memmap for PID {pid_str}", timeout_sec=300)
                if os.path.exists(cache_path): 
                    target_image = cache_path
                else:
                    for file in os.listdir(CACHE_DIR):
                        if file.startswith(f"pid.{pid_str}") and file.endswith(".dmp"):
                            target_image = os.path.join(CACHE_DIR, file)
                            break
            except Exception as e:
                ExecutionLogger.log("MCP_SERVER", f"Volatility extraction failed: {e}. Falling back to full memory.", "WARN")
                target_image = memory_image_path

    try:
        target_image = validate_path(target_image)
    except Exception as e:
        return f"[!] Path error: {e}"

    carve_cache_dir = os.path.join(CACHE_DIR, "carve_cache")
    os.makedirs(carve_cache_dir, exist_ok=True)
    hash_input = f"{regex_pattern}_{target_image}"
    cache_file = os.path.join(carve_cache_dir, f"strings_{hashlib.md5(hash_input.encode()).hexdigest()}.txt")
    
    if os.path.exists(cache_file):
        ExecutionLogger.log("MCP_SERVER", f"Using cached strings output: {cache_file}")
        with open(cache_file, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    ExecutionLogger.log("MCP_SERVER", f"Initializing streaming strings extraction on {target_image}")
    cmd = ["strings", "-a", target_image]

    if regex_pattern == "NETWORK" or "http" in regex_pattern.lower():
        inc_re = re.compile(r'(https?://|[a-zA-Z0-9.-]+\.(?:org|cn|biz|net|com|xyz|info)|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)', re.IGNORECASE)
        exc_re = re.compile(r'microsoft|windows|bing|akamai|live\.com|office\.com|skype\.com|digicert|verisign|local|w3\.org|127\.0\.0\.1|192\.168\.|10\.|outlook|slack|globalsign|quora|reddit|yahoo|youtube|qualtrics|zoom|amazon|adobe|pinterest', re.IGNORECASE)
    else:
        try:
            inc_re = re.compile(regex_pattern, re.IGNORECASE)
            exc_re = re.compile(r'microsoft', re.IGNORECASE)
        except Exception:
            ExecutionLogger.log("MCP_SERVER", "Invalid Regex Pattern provided.", "ERROR")
            return "[!] Invalid Regex Pattern"

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        matches = set()
        
        ExecutionLogger.log("MCP_SERVER", "Streaming strings output through regex filter...")
        for line in proc.stdout:
            if inc_re.search(line) and not exc_re.search(line):
                matches.add(line.strip())
            if len(matches) >= 300:
                ExecutionLogger.log("MCP_SERVER", "Hit 300 match limit, early termination.", "WARN")
                proc.kill()
                break
                
        proc.wait(timeout=120)
        
        if matches:
            ExecutionLogger.log("MCP_SERVER", f"Extracted {len(matches)} network indicators.", "SUCCESS")
            res = "\n".join(sorted(matches))
        else:
            ExecutionLogger.log("MCP_SERVER", "No network indicators found in memory.", "INFO")
            res = "[*] NULL HYPOTHESIS: No indicators found."
        
        with open(cache_file, "w", encoding="utf-8") as f:
            f.write(res)
        return res
    except subprocess.TimeoutExpired:
        ExecutionLogger.log("MCP_SERVER", "Memory carve timed out.", "ERROR")
        proc.kill()
        return "[!] MEMORY CARVE TIMEOUT"
    except Exception as e:
        ExecutionLogger.log("MCP_SERVER", f"Memory carve error: {e}", "ERROR")
        return f"[!] MEMORY CARVE ERROR: {e}"

def read_dfir_playbook() -> str:
    ExecutionLogger.log("MCP_SERVER", "Reading DFIR playbook.")
    if os.path.exists(PLAYBOOK_PATH):
        with open(PLAYBOOK_PATH, "r", encoding="utf-8") as f:
            return f.read()
    ExecutionLogger.log("MCP_SERVER", "Playbook not found.", "WARN")
    return "Playbook not found."
