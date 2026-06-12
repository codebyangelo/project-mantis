import subprocess
import os
import json
import time
import sys
import threading
import hashlib
import struct
import re
from config import EVIDENCE_DIR, CACHE_DIR, PLAYBOOK_PATH

def run_with_timer(cmd: str, task_name: str) -> str:
    """Executes a blocking subprocess while displaying a live timer on the console."""
    print(f"\n[TOOL START] {task_name}. STANDBY.")
    
    process_state = {"is_running": True, "output": "", "error": None}
    
    def target():
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            process_state["output"] = result.stdout
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
        raise Exception(process_state["error"])
        
    return process_state["output"]

def get_evidence_context() -> str:
    """Reads the contextual state of the investigation (HYBRID, MEMORY_ONLY, DISK_ONLY). MUST BE CALLED FIRST."""
    print("\n[TOOL START] Executing get_evidence_context()")
    path = os.path.join(CACHE_DIR, "context.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read()
    return '{"MODE": "UNKNOWN", "ERROR": "Context not built. Run extractor."}'

def resolve_username_from_pid(pid: str) -> str:
    """Helper to look up a username for a suspect PID in cmdline or pstree cache."""
    # 1. Try cmdline.json
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
            
    # 2. Try pstree.json
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
                    if u:
                        return u
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
    """
    Reads Volatility output cache natively and filters objects.
    Replaces brittle grep-based JSON parsing with robust Python dictionary filtering.
    """
    print(f"\n[TOOL START] Executing query_json_cache(cache='{cache_name}', keyword='{keyword}')")
    
    # --- REDIRECT PID REGISTRY QUERIES TO NTUSER HIVE ---
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
                    user_ntuser = []
                    for entry in reg_map["NTUSER"]:
                        if f"/{user}/" in entry.get("path", "").replace("\\", "/").lower():
                            user_ntuser.append(entry)
                    if user_ntuser:
                        result_dict["NTUSER"] = user_ntuser
                    else:
                        result_dict["NTUSER"] = reg_map["NTUSER"]
                elif "NTUSER" in reg_map:
                    result_dict["NTUSER"] = reg_map["NTUSER"]
                print(f"[*] Registry Map Query Redirected for PID {keyword_str} (User: '{user or 'unknown'}')")
                return json.dumps(result_dict, indent=2)
            except Exception as e:
                print(f"[!] Registry redirect failed: {e}")

    filepath = os.path.join(CACHE_DIR, f"{cache_name}.json")

    if not os.path.exists(filepath):
        return f"[!] Cache for {cache_name} not found."

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            raw_content = f.read()

        # --- NATIVE MALFIND PAGE_EXECUTE_READWRITE FILTER ---
        if cache_name == "malfind" and keyword == "PAGE_EXECUTE_READWRITE":
            try:
                data = json.loads(raw_content)
                pids = []
                for entry in data:
                    if entry.get("Protection") == "PAGE_EXECUTE_READWRITE":
                        pids.append(str(entry.get("PID")))
                pids = list(set(pids))
                if not pids:
                    return "[*] No PAGE_EXECUTE_READWRITE segments found."
                return f"[*] Identified PIDs with PAGE_EXECUTE_READWRITE segments: {', '.join(pids)}\n[DIRECTIVE] You MUST iterate through these PIDs one by one."
            except Exception:
                pass
        # ----------------------------------------------------

        if not keyword:
            if len(raw_content) > 50000:
                return f"[!] SYSTEM DENIAL: Payload too large. Use a keyword (like a PID) to filter {cache_name}."
            return raw_content

        # Native JSON parsing for exact filtering (Zero-Grep / Zero-jq)
        try:
            data = json.loads(raw_content)
            if isinstance(data, list):
                filtered_list = []
                keyword_str = str(keyword).lower()
                for entry in data:
                    if isinstance(entry, dict):
                        # Match if keyword matches any value or key
                        match = False
                        for k, v in entry.items():
                            if keyword_str in str(k).lower() or keyword_str in str(v).lower():
                                match = True
                                break
                        if match:
                            filtered_list.append(entry)
                if filtered_list:
                    out = json.dumps(filtered_list, indent=2)
                    if len(out) > 8000:
                        return out[:8000] + "\n\n[!] OUTPUT TRUNCATED: Too many matches. Refine your keyword."
                    return out
                else:
                    return f"[*] Keyword '{keyword}' not found in list elements of {cache_name}."
            elif isinstance(data, dict):
                filtered_dict = {}
                keyword_str = str(keyword).lower()
                for k, v in data.items():
                    if keyword_str in str(k).lower() or keyword_str in str(v).lower():
                        filtered_dict[k] = v
                if filtered_dict:
                    return json.dumps(filtered_dict, indent=2)
        except json.JSONDecodeError:
            pass

        # Fallback to line-by-line grep matching
        matched_lines = []
        for line in raw_content.splitlines():
            if keyword.lower() in line.lower():
                matched_lines.append(line.strip())
        
        if not matched_lines:
            return f"[*] Keyword '{keyword}' not found in {cache_name}."
            
        result = "\n".join(matched_lines)
        if len(result) > 8000:
            return result[:8000] + "\n\n[!] OUTPUT TRUNCATED: Too many matches. Refine your keyword."
        return result

    except Exception as e:
        return f"[!] Error parsing cache: {e}"

def extract_and_carve_hive(inode: str, disk_image_path: str) -> str:
    """Carves DLL configuration paths from registry. Fallback recursively checks directories if icat is absent."""
    task_name = f"Physical Hive Extraction & Carve (Inode: {inode})"
    print(f"\n[TOOL START] {task_name}")
    
    # 1. Search for pre-extracted hive files in EVIDENCE_DIR if the E01 is missing/unreadable
    fallback_file = None
    if not os.path.exists(disk_image_path):
        print(f"[*] Disk image not found at {disk_image_path}. Searching local directories for pre-extracted hives...")
        for root, dirs, files in os.walk(EVIDENCE_DIR):
            for file in files:
                if file.upper() in ["SYSTEM", "SOFTWARE", "NTUSER.DAT"]:
                    fallback_file = os.path.join(root, file)
                    print(f"    [+] Found pre-extracted hive file: {fallback_file}")
                    break
            if fallback_file:
                break

    if fallback_file:
        try:
            print(f"[*] Extracting strings directly from pre-extracted file: {fallback_file}")
            cmd = (
                f"strings -el '{fallback_file}' | grep -Fi 'C:\\' | grep -i '\\.dll' | "
                f"grep -ivE 'system32|syswow64|winsxs|program files|microsoft\\.net' | sort -u"
            )
            output = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()
            if not output:
                return "[*] HIVE CARVE CLEAN: No anomalous absolute DLL paths found."
            return f"[!] ANOMALY DETECTED IN HIVE (Fallback Search):\n{output}"
        except Exception as e:
            return f"[!] Fallback carve error: {e}"

    # 2. Standard icat command execution
    try:
        cmd = (
            f"icat -i ewf {disk_image_path} {inode} | "
            f"strings -el | grep -Fi 'C:\\' | grep -i '\\.dll' | "
            f"grep -ivE 'system32|syswow64|winsxs|program files|microsoft\\.net' | sort -u"
        )
        output = run_with_timer(cmd, task_name).strip()
        if not output:
            return "[*] HIVE CARVE CLEAN: No anomalous absolute DLL paths found. If memory shows compromise, injection is purely fileless."
        return f"[!] ANOMALY DETECTED IN HIVE:\n{output}"
    except Exception as e:
        print(f"[!] icat failed: {e}. Attempting directory search fallback...")
        # Final directory search fallback if command failed
        for root, dirs, files in os.walk(EVIDENCE_DIR):
            for file in files:
                if file.upper() in ["SYSTEM", "SOFTWARE", "NTUSER.DAT"]:
                    try:
                        cmd = (
                            f"strings -el '{os.path.join(root, file)}' | grep -Fi 'C:\\' | grep -i '\\.dll' | "
                            f"grep -ivE 'system32|syswow64|winsxs|program files|microsoft\\.net' | sort -u"
                        )
                        output = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()
                        if output:
                            return f"[!] ANOMALY DETECTED IN HIVE (Recursive Fallback):\n{output}"
                    except Exception:
                        pass
        return f"[!] HIVE CARVE ERROR: {e}"

def carve_memory_strings(regex_pattern: str, memory_image_path: str, pid: str = "NONE") -> str:
    """Carves strings from raw memory. Utilizes local file cache to prevent duplicate disk reads."""
    # 1. Resolve target file (check pre-extracted process memory dumps first)
    target_image = memory_image_path
    pid_str = str(pid).strip()
    
    if pid_str.isdigit():
        loose_path = os.path.join(EVIDENCE_DIR, "loose_data", f"pid.{pid_str}.dmp")
        cache_path = os.path.join(CACHE_DIR, f"pid.{pid_str}.dmp")
        
        if os.path.exists(loose_path):
            target_image = loose_path
            print(f"[*] Found pre-existing process memory dump in loose_data: {target_image}")
        elif os.path.exists(cache_path):
            target_image = cache_path
            print(f"[*] Found pre-existing process memory dump in cache: {target_image}")
        else:
            # Check if this PID has active network bindings to warrant an 8-minute Volatility memory dump
            has_network = False
            netscan_path = os.path.join(CACHE_DIR, "netscan.json")
            if os.path.exists(netscan_path):
                try:
                    with open(netscan_path, "r", encoding="utf-8") as f:
                        netscan_data = json.load(f)
                        for entry in netscan_data:
                            if str(entry.get("PID")) == pid_str:
                                foreign = entry.get("ForeignAddr")
                                if foreign and foreign not in ["*", "0.0.0.0", "::"]:
                                    has_network = True
                                    break
                except Exception:
                    pass
            
            if not has_network:
                print(f"[*] Skipping dynamic Volatility memmap dump for PID {pid_str} (no active outbound connections found).")
                return "[*] NULL HYPOTHESIS MET: Skipping memory carve for PID without active outbound network connections."

            # Dynamically extract process memory using Volatility 3
            vol_cmd = f"vol -o '{CACHE_DIR}' -f '{memory_image_path}' windows.memmap --pid {pid_str} --dump"
            try:
                print(f"[*] Process memory dump not found. Running Volatility 3 to extract PID {pid_str} memmap...")
                run_with_timer(vol_cmd, f"Dumping memory space for PID {pid_str}")
                if os.path.exists(cache_path):
                    target_image = cache_path
                else:
                    # Search for any generated pid.<pid>*.dmp file (sometimes volatility adds suffix)
                    for file in os.listdir(CACHE_DIR):
                        if file.startswith(f"pid.{pid_str}") and file.endswith(".dmp"):
                            target_image = os.path.join(CACHE_DIR, file)
                            break
            except Exception as e:
                print(f"[!] Volatility memmap dump failed: {e}. Falling back to global raw memory file.")
                target_image = memory_image_path

    # 2. Setup Caching Directory
    carve_cache_dir = os.path.join(CACHE_DIR, "carve_cache")
    os.makedirs(carve_cache_dir, exist_ok=True)
    
    # 3. Compute query hash to identify cache hits (use target_image in hash)
    hash_input = f"{regex_pattern}_{target_image}"
    pattern_hash = hashlib.md5(hash_input.encode('utf-8')).hexdigest()
    cache_file = os.path.join(carve_cache_dir, f"strings_{pattern_hash}.txt")
    
    if os.path.exists(cache_file):
        print(f"\n[TOOL START] Carving Memory for: '{regex_pattern}' (Target: {os.path.basename(target_image)})")
        print(f"[*] Cache Hit! Loading carved strings in milliseconds from: {cache_file}")
        with open(cache_file, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    # 4. Cache Miss - Run the heavy carving command
    if regex_pattern == "NETWORK" or "http" in regex_pattern.lower():
        task_name = f"Carving Memory for: Network Indicators (Target: {os.path.basename(target_image)})"
        # Extract URLs, domains, and routable IPv4 addresses while filtering out common OS/telemetry domains
        cmd = (
            f"strings -a '{target_image}' | "
            f"grep -iE '(https?://|[a-zA-Z0-9.-]+\\.(org|cn|biz|net|com|xyz|info)|\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b)' | "
            f"grep -ivE 'microsoft|windows|bing|akamai|live\\.com|office\\.com|skype\\.com|digicert|verisign|local|w3\\.org|127\\.0\\.0\\.1|192\\.168\\.|10\\.|outlook|slack|globalsign|quora|reddit|yahoo|youtube|qualtrics|zoom|amazon|adobe|pinterest' | "
            f"sort -u | head -n 300"
        )
    else:
        task_name = f"Carving Memory for: '{regex_pattern}' (Target: {os.path.basename(target_image)})"
        cmd = (
            f"strings -a '{target_image}' | "
            f"grep -iE '{regex_pattern}' | "
            f"grep -v 'microsoft' | sort -u | head -n 30"
        )

    try:
        output = run_with_timer(cmd, task_name)
        result = output if output.strip() else "[*] NULL HYPOTHESIS MET: No external routable indicators found."
        
        # Write to cache
        with open(cache_file, "w", encoding="utf-8") as f:
            f.write(result)
            
        return result
    except Exception as e:
        return f"[!] MEMORY CARVE ERROR: {e}"

def read_dfir_playbook() -> str:
    print(f"\n[TOOL START] Executing read_dfir_playbook()")
    if os.path.exists(PLAYBOOK_PATH):
        with open(PLAYBOOK_PATH, "r", encoding="utf-8") as f:
            return f.read()
    return "Playbook not found."
