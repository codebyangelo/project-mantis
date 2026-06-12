import subprocess
import os
import json
import time
import sys
import threading
import hashlib
import re
from config import EVIDENCE_DIR, CACHE_DIR, PLAYBOOK_PATH

def validate_path(path_str: str) -> str:
    """Validates and resolves a path against allowed sandbox directories to prevent traversal."""
    if not isinstance(path_str, str) or "\x00" in path_str:
        raise ValueError("Invalid path format.")
    
    real_p = os.path.realpath(path_str)
    allowed = [os.path.realpath(EVIDENCE_DIR), os.path.realpath(CACHE_DIR)]
    
    if not any(real_p.startswith(a) for a in allowed):
        raise ValueError(f"Path traversal attempt blocked: {path_str}")
    return real_p

def run_with_timer(cmd: list, task_name: str, timeout_sec: int = 120) -> str:
    """Executes a blocking subprocess without shell=True, enforcing a timeout."""
    print(f"\n[TOOL START] {task_name}. STANDBY.")
    
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
        print("\n[!] Timer interrupted by user.")
        pass
        
    worker.join()
    print("\n[+] Task Complete.")
    
    if process_state["error"]:
        raise Exception(str(process_state["error"]))
        
    return process_state["output"]

def get_evidence_context() -> str:
    """Reads the contextual state of the investigation."""
    print("\n[TOOL START] Executing get_evidence_context()")
    path = os.path.join(CACHE_DIR, "context.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read()
    return '{"MODE": "UNKNOWN", "ERROR": "Context not built. Run extractor."}'

def resolve_username_from_pid(pid: str) -> str:
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
                            return match.group(1)
        except Exception:
            pass
            
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
                    if u: return u
            else:
                return find_user_in_tree(pstree)
        except Exception:
            pass
    return ""

def query_json_cache(cache_name: str, keyword: str = "") -> str:
    """Reads Volatility output cache natively and filters objects."""
    print(f"\n[TOOL START] Executing query_json_cache(cache='{cache_name}', keyword='{keyword}')")
    
    if not re.match(r"^[a-zA-Z0-9_]+$", cache_name):
        return "[!] Invalid cache name."
        
    keyword_str = str(keyword).strip()
    if cache_name == "registry_map" and keyword_str.isdigit():
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
                print(f"[*] Registry Map Query Redirected for PID {keyword_str}")
                return json.dumps(result_dict, indent=2)
            except Exception as e:
                print(f"[!] Registry redirect failed: {e}")

    try:
        filepath = validate_path(os.path.join(CACHE_DIR, f"{cache_name}.json"))
    except Exception as e:
        return f"[!] {e}"

    if not os.path.exists(filepath):
        return f"[!] Cache for {cache_name} not found."

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            raw_content = f.read()

        if cache_name == "malfind" and keyword == "PAGE_EXECUTE_READWRITE":
            try:
                data = json.loads(raw_content)
                pids = list({str(entry.get("PID")) for entry in data if entry.get("Protection") == "PAGE_EXECUTE_READWRITE"})
                if not pids:
                    return "[*] No PAGE_EXECUTE_READWRITE segments found."
                return f"[*] Identified PIDs with PAGE_EXECUTE_READWRITE segments: {', '.join(pids)}"
            except Exception:
                pass

        if not keyword:
            if len(raw_content) > 50000:
                return f"[!] Payload too large. Use a keyword."
            return raw_content

        try:
            data = json.loads(raw_content)
            if isinstance(data, list):
                keyword_str = str(keyword).lower()
                filtered = [e for e in data if isinstance(e, dict) and any(keyword_str in str(k).lower() or keyword_str in str(v).lower() for k, v in e.items())]
                if filtered:
                    out = json.dumps(filtered, indent=2)
                    return out[:8000] + "\n\n[!] OUTPUT TRUNCATED" if len(out) > 8000 else out
                return f"[*] Keyword '{keyword}' not found."
            elif isinstance(data, dict):
                keyword_str = str(keyword).lower()
                filtered = {k: v for k, v in data.items() if keyword_str in str(k).lower() or keyword_str in str(v).lower()}
                if filtered:
                    return json.dumps(filtered, indent=2)
        except json.JSONDecodeError:
            pass

        matched = [line.strip() for line in raw_content.splitlines() if keyword.lower() in line.lower()]
        if not matched:
            return f"[*] Keyword '{keyword}' not found."
        res = "\n".join(matched)
        return res[:8000] + "\n\n[!] OUTPUT TRUNCATED" if len(res) > 8000 else res

    except Exception as e:
        return f"[!] Error parsing cache: {e}"

def extract_and_carve_hive(inode: str, disk_image_path: str) -> str:
    """Carves DLL configuration paths natively without shell=True."""
    task_name = f"Physical Hive Extraction (Inode: {inode})"
    print(f"\n[TOOL START] {task_name}")
    
    if not re.fullmatch(r"[\d\-]+", str(inode)):
        return "[!] FATAL: Invalid inode format."
        
    try:
        disk_image_path = validate_path(disk_image_path)
    except Exception as e:
        return f"[!] Path validation failed: {e}"

    if not os.path.exists(disk_image_path):
        return "[!] Disk image not found."

    try:
        icat_cmd = ["icat", "-i", "ewf", disk_image_path, inode]
        strings_cmd = ["strings", "-el"]
        
        icat_proc = subprocess.Popen(icat_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        strings_proc = subprocess.Popen(strings_cmd, stdin=icat_proc.stdout, stdout=subprocess.PIPE, text=True)
        icat_proc.stdout.close()
        
        output, err = strings_proc.communicate(timeout=120)
        
        if strings_proc.returncode != 0:
            return f"[!] Strings pipeline failed: {err.strip()}"
            
        exclusions = ['system32', 'syswow64', 'winsxs', 'program files', 'microsoft.net']
        results = set()
        for line in output.splitlines():
            line_lower = line.lower()
            if 'c:\\' in line_lower and '.dll' in line_lower:
                if not any(excl in line_lower for excl in exclusions):
                    results.add(line.strip())
        
        if not results:
            return "[*] HIVE CARVE CLEAN: No anomalous absolute DLL paths found."
        return "[!] ANOMALY DETECTED IN HIVE:\n" + "\n".join(sorted(results))
    except subprocess.TimeoutExpired:
        icat_proc.kill()
        strings_proc.kill()
        return "[!] ERROR: Forensic carve timed out after 120s."
    except Exception as e:
        return f"[!] HIVE CARVE ERROR: {e}"

def carve_memory_strings(regex_pattern: str, memory_image_path: str, pid: str = "NONE") -> str:
    """Streams strings output in Python instead of buffering to RAM."""
    pid_str = str(pid).strip()
    target_image = memory_image_path
    
    if pid_str.isdigit():
        loose_path = os.path.join(EVIDENCE_DIR, "loose_data", f"pid.{pid_str}.dmp")
        cache_path = os.path.join(CACHE_DIR, f"pid.{pid_str}.dmp")
        if os.path.exists(loose_path):
            target_image = loose_path
        elif os.path.exists(cache_path):
            target_image = cache_path
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
                return "[*] NULL HYPOTHESIS: Skipping memory carve (no network)."

            vol_cmd = ["vol", "-o", CACHE_DIR, "-f", memory_image_path, "windows.memmap", "--pid", pid_str, "--dump"]
            try:
                run_with_timer(vol_cmd, f"Dumping memmap for PID {pid_str}", timeout_sec=300)
                if os.path.exists(cache_path): target_image = cache_path
                else:
                    for file in os.listdir(CACHE_DIR):
                        if file.startswith(f"pid.{pid_str}") and file.endswith(".dmp"):
                            target_image = os.path.join(CACHE_DIR, file)
                            break
            except Exception as e:
                print(f"[!] Volatility failed: {e}. Fallback to full memory.")
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
        with open(cache_file, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    task_name = f"Carving Memory: {regex_pattern}"
    print(f"\n[TOOL START] {task_name}")
    cmd = ["strings", "-a", target_image]

    if regex_pattern == "NETWORK" or "http" in regex_pattern.lower():
        inc_re = re.compile(r'(https?://|[a-zA-Z0-9.-]+\.(?:org|cn|biz|net|com|xyz|info)|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)', re.IGNORECASE)
        exc_re = re.compile(r'microsoft|windows|bing|akamai|live\.com|office\.com|skype\.com|digicert|verisign|local|w3\.org|127\.0\.0\.1|192\.168\.|10\.|outlook|slack|globalsign|quora|reddit|yahoo|youtube|qualtrics|zoom|amazon|adobe|pinterest', re.IGNORECASE)
    else:
        try:
            inc_re = re.compile(regex_pattern, re.IGNORECASE)
            exc_re = re.compile(r'microsoft', re.IGNORECASE)
        except Exception:
            return "[!] Invalid Regex Pattern"

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        matches = set()
        
        for line in proc.stdout:
            if inc_re.search(line) and not exc_re.search(line):
                matches.add(line.strip())
            if len(matches) >= 300:
                proc.kill()
                break
                
        proc.wait(timeout=120)
        res = "\n".join(sorted(matches)) if matches else "[*] NULL HYPOTHESIS: No indicators found."
        
        with open(cache_file, "w", encoding="utf-8") as f:
            f.write(res)
        return res
    except subprocess.TimeoutExpired:
        proc.kill()
        return "[!] MEMORY CARVE TIMEOUT"
    except Exception as e:
        return f"[!] MEMORY CARVE ERROR: {e}"

def read_dfir_playbook() -> str:
    print(f"\n[TOOL START] Executing read_dfir_playbook()")
    if os.path.exists(PLAYBOOK_PATH):
        with open(PLAYBOOK_PATH, "r", encoding="utf-8") as f:
            return f.read()
    return "Playbook not found."
