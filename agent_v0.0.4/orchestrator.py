#!/usr/bin/env python3
# orchestrator.py
import sys
import os
import time
import subprocess
import re
import json
from mcp_server import execute_live_mcp_restricted
from agent import FindEvilAgent

# --- SYSTEM PATH CONFIGURATIONS ---
DEFAULT_IMAGE_PATH = "/mnt/sift_ext4/evidence/Rocba-Memory/Rocba-Memory.raw"
DEFAULT_E01_PATH = "/media/analyst/external_drive/project_data/rocba-cdrive.e01"
DEFAULT_PROFILE_PATH = "/mnt/sift_ext4/findevil_triage_profile.json"

# --- TELEMETRY PARSING & HELPER FUNCTIONS ---

def parse_pstree(pstree_raw):
    """
    Parses Volatility windows.pstree output.
    Cleans up visual tree decoration (stars, dots, dashes, spaces) at the start of lines.
    """
    pstree_map = {}
    pid_pattern = re.compile(r'^(\d+)\s+(\d+)\s+(\S+)')
    
    for line in pstree_raw.splitlines():
        line = line.strip()
        # Strip leading visual tree decoration (e.g. *, ., -, and spaces) before the first digit
        cleaned_line = re.sub(r'^[ \*\.\-]+', '', line).strip()
        match = pid_pattern.match(cleaned_line)
        if match:
            pid = int(match.group(1))
            ppid = int(match.group(2))
            name = match.group(3)
            pstree_map[pid] = {
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "args": "",
                "suspicious": False,
                "malfind_output": "",
                "fls_output": "",
                "fls_node": ""
            }
    return pstree_map

def parse_cmdline(cmdline_raw):
    """
    Parses Volatility windows.cmdline output.
    Maps PID to its arguments string.
    """
    cmdline_map = {}
    cmdline_pattern = re.compile(r'^(\d+)\s+(\S+)\s+(.*)$')
    
    for line in cmdline_raw.splitlines():
        line = line.strip()
        match = cmdline_pattern.match(line)
        if match:
            pid = int(match.group(1))
            args = match.group(3).strip()
            # In case of duplicates, keep the longer args
            if pid not in cmdline_map or len(args) > len(cmdline_map[pid]):
                cmdline_map[pid] = args
    return cmdline_map

def extract_executable_path(cmdline):
    """
    Extracts the executable path from a Windows command line string.
    """
    cmdline = cmdline.strip()
    if not cmdline or cmdline == "-":
        return ""
    if cmdline.startswith('"'):
        end = cmdline.find('"', 1)
        if end != -1:
            return cmdline[1:end]
        return cmdline[1:]
    return cmdline.split()[0]

def is_suspicious_path(path):
    """
    Heuristic rule to check if execution path is suspicious.
    """
    path_lower = path.lower()
    return "appdata" in path_lower or "temp" in path_lower or "public" in path_lower

def get_path_parts(exec_path):
    """
    Normalizes a Windows path, strips drive letters/prefixes,
    discards the executable name, and returns directory path parts.
    """
    path = exec_path.replace('/', '\\')
    if path.startswith('\\??\\'):
        path = path[4:]
    elif path.startswith('\\\\?\\'):
        path = path[4:]
        
    if len(path) >= 2 and path[1] == ':':
        path = path[2:]
        
    parts = [p for p in path.split('\\') if p]
    if parts:
        # Discard the last part (the filename)
        parts.pop()
    return parts

# --- E01 DIRECTORY PATH RESOLUTION ---

NODE_CACHE = {}

def resolve_node_for_path_parts(e01_path, parts):
    """
    Sequentially walks directory path parts in the E01 image using fls.
    Returns the target folder node string if found, else None.
    Uses NODE_CACHE to optimize walks on slow mechanical HDDs.
    """
    current_node = "" # Empty starts at root
    resolved_parts = []
    
    for part in parts:
        resolved_parts.append(part.lower())
        cache_key = "\\".join(resolved_parts)
        if cache_key in NODE_CACHE:
            current_node = NODE_CACHE[cache_key]
            continue
            
        cmd = ["fls", "-i", "ewf", e01_path]
        if current_node:
            cmd.append(current_node)
        
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"    [!] fls command failed on node '{current_node}'")
            return None
            
        next_node = None
        for line in proc.stdout.splitlines():
            # Match standard fls directory output format:
            # d/d 282867-144-5:       Users
            # d/d * 282867-144-5:     Users
            match = re.search(r'^[dr]/[dr]\s+[\*]?\s*(\d+)(?:-\d+-\d+)?:\s+(.*)$', line.strip())
            if match:
                node_str = match.group(1)
                name = match.group(2).strip()
                if name.lower() == part.lower():
                    next_node = node_str
                    break
        if not next_node:
            print(f"    [!] Could not resolve path part '{part}' under node '{current_node}'")
            return None
        current_node = next_node
        NODE_CACHE[cache_key] = current_node
        
    return current_node

def parse_and_clean_malfind(process_name, malfind_stdout):
    """
    Parses malfind output and filters out VAD regions containing only 00 bytes
    for known JIT-heavy processes (Teams.exe, Slack.exe, chrome.exe, msedge.exe).
    """
    if not malfind_stdout:
        return malfind_stdout
        
    process_lower = process_name.lower()
    is_jit_heavy = any(x in process_lower for x in ["teams.exe", "slack.exe", "chrome.exe", "msedge.exe"])
    
    if not is_jit_heavy:
        return malfind_stdout
        
    lines = malfind_stdout.splitlines()
    cleaned_lines = []
    current_block_header = None
    current_block_hex_lines = []
    current_block_disasm_lines = []
    
    def process_and_append_block(header, hex_lines, disasm_lines):
        is_all_zeros = True
        has_hex = False
        for line in hex_lines:
            parts = line.strip().split()
            if not parts:
                continue
            hex_parts = []
            for p in parts:
                if len(p) == 2 and all(c in '0123456789abcdefABCDEF' for c in p):
                    hex_parts.append(p)
                else:
                    break
            if hex_parts:
                has_hex = True
                if any(h != "00" for h in hex_parts):
                    is_all_zeros = False
                    break
                    
        if has_hex and is_all_zeros:
            cleaned_lines.append(header)
            cleaned_lines.append("    [INFO] VAD region filtered: hex dump consists entirely of 00 bytes (benign JIT compiler page).")
        else:
            cleaned_lines.append(header)
            cleaned_lines.extend(hex_lines)
            cleaned_lines.extend(disasm_lines)

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("PID") or line.startswith("Volatility"):
            cleaned_lines.append(line)
            i += 1
            continue
        if not line.strip():
            cleaned_lines.append(line)
            i += 1
            continue
            
        parts = line.split('\t')
        if len(parts) >= 6 and parts[0].isdigit():
            if current_block_header:
                process_and_append_block(
                    current_block_header,
                    current_block_hex_lines,
                    current_block_disasm_lines
                )
            current_block_header = line
            current_block_hex_lines = []
            current_block_disasm_lines = []
        elif current_block_header:
            if ":" in line and line.strip().startswith("0x"):
                current_block_disasm_lines.append(line)
            else:
                current_block_hex_lines.append(line)
        else:
            cleaned_lines.append(line)
        i += 1
        
    if current_block_header:
        process_and_append_block(
            current_block_header,
            current_block_hex_lines,
            current_block_disasm_lines
        )
        
    return "\n".join(cleaned_lines)

def parse_and_clean_fls(fls_stdout, exec_path):
    """
    Processes fls output. When identifying api-ms-win-* or ucrtbase.dll files
    within known software deployment paths (AppData, Program Files), we classify/annotate
    them as benign App-Local Deployment artifacts.
    """
    if not fls_stdout:
        return fls_stdout
        
    path_lower = exec_path.lower()
    is_known_deployment_path = "appdata" in path_lower or "program files" in path_lower
    
    lines = fls_stdout.splitlines()
    cleaned_lines = []
    
    for line in lines:
        line_lower = line.lower()
        is_target_dll = "api-ms-win-" in line_lower or "ucrtbase.dll" in line_lower
        
        if is_known_deployment_path and is_target_dll:
            cleaned_lines.append(f"{line} [INFO: Benign App-Local Deployment UCRT artifact]")
        else:
            cleaned_lines.append(line)
            
    return "\n".join(cleaned_lines)

# --- PERSISTENCE STATE MANAGEMENT ---


def load_triage_profile(profile_path):
    if os.path.exists(profile_path):
        try:
            with open(profile_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Warning: Failed to load profile: {e}")
    return None

def save_triage_profile(profile_path, profile):
    try:
        with open(profile_path, 'w', encoding='utf-8') as f:
            json.dump(profile, f, indent=2)
        print(f"    [+] Saved profile state to {profile_path}")
    except Exception as e:
        print(f"[!] Failed to save profile state: {e}")

# --- THE THREE-PHASE AUTOMATION ENGINE ---

def run_automation_engine(image_path, e01_path, profile_path):
    print("\n" + "="*60)
    print("[ RUNNING AUTOMATED DFIR TRIAGE ENGINE ]")
    print("="*60)
    
    profile = load_triage_profile(profile_path)
    if profile:
        print(f"[*] Recovered saved state from {profile_path}")
    else:
        profile = {
            "image_path": image_path,
            "e01_path": e01_path,
            "phases_completed": [],
            "processes": {}
        }
        
    # Phase 1: High-Speed Triage & In-Memory Mapping
    if "phase1" not in profile["phases_completed"]:
        print("\n[PHASE 1] High-Speed Triage & In-Memory Mapping")
        
        # 1. Capture Process Tree
        print("[*] Executing windows.pstree...")
        pstree_proc = subprocess.run(["vol", "-f", image_path, "windows.pstree"], capture_output=True, text=True)
        if pstree_proc.returncode != 0:
            print(f"[!] ERROR: pstree command failed: {pstree_proc.stderr}")
            sys.exit(1)
            
        # Cache raw pstree stdout
        try:
            with open("/mnt/sift_ext4/pstree_raw.txt", "w", encoding="utf-8") as f:
                f.write(pstree_proc.stdout)
        except Exception as e:
            print(f"[!] Warning: Failed to cache raw pstree: {e}")
            
        # 2. Capture Command Line arguments
        print("[*] Executing windows.cmdline...")
        cmdline_proc = subprocess.run(["vol", "-f", image_path, "windows.cmdline"], capture_output=True, text=True)
        if cmdline_proc.returncode != 0:
            print(f"[!] ERROR: cmdline command failed: {cmdline_proc.stderr}")
            sys.exit(1)
            
        # Cache raw cmdline stdout
        try:
            with open("/mnt/sift_ext4/cmdline_raw.txt", "w", encoding="utf-8") as f:
                f.write(cmdline_proc.stdout)
        except Exception as e:
            print(f"[!] Warning: Failed to cache raw cmdline: {e}")
            
        # Parse inputs
        print("[*] Parsing pstree and cmdline outputs...")
        processes = parse_pstree(pstree_proc.stdout)
        cmdline_map = parse_cmdline(cmdline_proc.stdout)
        
        # Merge
        for pid, p_info in processes.items():
            if pid in cmdline_map:
                p_info["args"] = cmdline_map[pid]
                
        profile["processes"] = {str(k): v for k, v in processes.items()}
        profile["phases_completed"].append("phase1")
        save_triage_profile(profile_path, profile)
    else:
        print("\n[PHASE 1] [SKIPPED] Already completed.")

    # Phase 2: Core Decision Engine
    if "phase2" not in profile["phases_completed"]:
        print("\n[PHASE 2] Core Decision Engine & Heuristic Filtering")
        
        LOLBINS_LIST = ["rundll32.exe", "regsvr32.exe", "powershell.exe", "cmd.exe", "spoolsv.exe", "lsass.exe"]
        suspicious_count = 0
        for pid_str, p_info in profile["processes"].items():
            args = p_info.get("args", "")
            exec_path = extract_executable_path(args)
            name_lower = p_info.get("name", "").lower()
            # Flag if running from suspicious path or if it is a target LOLBin / frequent process
            if is_suspicious_path(exec_path) or name_lower in LOLBINS_LIST:
                p_info["suspicious"] = True
                suspicious_count += 1
                print(f"    [!] Flagged Suspicious PID {pid_str}: {p_info['name']} -> path: {exec_path}")
                
        print(f"[*] Heuristic Filtering complete. Isolated {suspicious_count} suspicious processes.")
        profile["phases_completed"].append("phase2")
        save_triage_profile(profile_path, profile)
    else:
        print("\n[PHASE 2] [SKIPPED] Already completed.")

    # Phase 3: Targeted Storage & Memory Strikes
    if "phase3" not in profile["phases_completed"]:
        print("\n[PHASE 3] Targeted Storage & Memory Strikes")
        
        suspicious_pids = [pid_str for pid_str, p_info in profile["processes"].items() if p_info.get("suspicious")]
        
        for pid_str in suspicious_pids:
            p_info = profile["processes"][pid_str]
            # Skip if already run for this PID
            if p_info.get("malfind_output") and p_info.get("fls_output"):
                print(f"[*] Strikes already executed for PID {pid_str}. Skipping.")
                continue
                
            print(f"\n[*] Launching precision strikes for PID {pid_str} ({p_info['name']})...")
            
            # Strike 1: Targeted malfind
            print(f"    [+] Running targeted malfind for PID {pid_str}...")
            malfind_proc = subprocess.run(["vol", "-f", image_path, "windows.malfind", "--pid", pid_str], capture_output=True, text=True)
            raw_malfind = malfind_proc.stdout if malfind_proc.returncode == 0 else f"Error running malfind: {malfind_proc.stderr}"
            p_info["malfind_output"] = parse_and_clean_malfind(p_info['name'], raw_malfind)
            
            # Strike 2: Localized fls lookup (only run E01 walks if the path is suspicious)
            args = p_info.get("args", "")
            exec_path = extract_executable_path(args)
            if is_suspicious_path(exec_path):
                path_parts = get_path_parts(exec_path)
                path_str = '\\'.join(path_parts)
                print(f"    [+] Resolving directory node for path: {path_str}")
                node = resolve_node_for_path_parts(e01_path, path_parts)
                if node:
                    print(f"    [+] Directory node resolved to: {node}")
                    p_info["fls_node"] = node
                    fls_proc = subprocess.run(["fls", "-i", "ewf", e01_path, node], capture_output=True, text=True)
                    raw_fls = fls_proc.stdout if fls_proc.returncode == 0 else f"Error running fls: {fls_proc.stderr}"
                    p_info["fls_output"] = parse_and_clean_fls(raw_fls, exec_path)
                else:
                    p_info["fls_node"] = "None"
                    p_info["fls_output"] = "Could not resolve path node in E01 image."
            else:
                p_info["fls_node"] = "Skipped"
                p_info["fls_output"] = "Fls lookup skipped for benign/standard execution path."
                
            save_triage_profile(profile_path, profile)
            
        profile["phases_completed"].append("phase3")
        save_triage_profile(profile_path, profile)
        print("\n[*] Precision strikes completed successfully.")
    else:
        print("\n[PHASE 3] [SKIPPED] Already completed.")
        
    print("\n" + "="*60)
    print("[ AUTOMATED TRIAGE COMPLETE ]")
    print("="*60 + "\n")
    return profile

# --- AGENT TOOLS ---

def record_cognitive_process(thought_process: str) -> str:
    print("\n" + "-"*60)
    print("[BLOCK] Cognitive State Logging")
    print("[ACTION] Writing agent hypothesis to 'thoughts.txt'.")
    try:
        with open("thoughts.txt", "a", encoding='utf-8') as f:
            f.write(f"[THOUGHT] {thought_process}\n")
        print(f"    └── \"{thought_process[:60]}...\"")
        print("[STATUS] [SUCCESS] Thought committed to disk.")
        time.sleep(1)
        print("-" * 60)
        return "Thought logged successfully. Proceed with your intended action."
    except Exception as e:
        print(f"[STATUS] [FAILED] File I/O Error: {str(e)}")
        print("-" * 60)
        return f"Error logging thought: {str(e)}"

def query_triage_profile() -> str:
    """
    Returns the final structured JSON telemetry profile of the system triage.
    This includes process tree mappings, flagged PIDs, targeted malfind memory injection results,
    and target fls listings.
    """
    print("\n" + "-"*60)
    print("[BLOCK] Telemetry Profile Request")
    print("[ACTION] Reading structured JSON profile from disk...")
    
    if os.path.exists(DEFAULT_PROFILE_PATH):
        try:
            with open(DEFAULT_PROFILE_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            summary_profile = {
                "image_path": data.get("image_path"),
                "e01_path": data.get("e01_path"),
                "total_processes": len(data.get("processes", {})),
                "suspicious_processes": {}
            }
            
            for pid, p_info in data.get("processes", {}).items():
                if p_info.get("suspicious"):
                    summary_profile["suspicious_processes"][pid] = p_info
                    
            print(f"[STATUS] [SUCCESS] Extracted summary profile. Total suspicious processes: {len(summary_profile['suspicious_processes'])}")
            print("-" * 60)
            return json.dumps(summary_profile, indent=2)
        except Exception as e:
            print(f"[STATUS] [FAILED] Error: {str(e)}")
            print("-" * 60)
            return f"Error reading triage profile: {str(e)}"
    print("[STATUS] [FAILED] Profile file not found.")
    print("-" * 60)
    return "Error: Triage profile not found on disk."

def test_live_mcp_connection(plugin_name: str) -> str:
    return execute_live_mcp_restricted(plugin_name)

def parse_windows_path(file_path):
    """
    Parses a Windows file path into directory parts and a filename.
    """
    path = file_path.replace('/', '\\')
    if path.startswith('\\??\\'):
        path = path[4:]
    elif path.startswith('\\\\?\\'):
        path = path[4:]
    if len(path) >= 2 and path[1] == ':':
        path = path[2:]
        
    parts = [p for p in path.split('\\') if p]
    if not parts:
        return [], ""
    filename = parts[-1]
    dir_parts = parts[:-1]
    return dir_parts, filename

def extract_and_hash_by_path(file_path: str) -> str:
    """
    Resolves, extracts, and computes the SHA-256 hash of a file directly from the E01 disk image.
    Saves the extracted file to /mnt/sift_ext4/extracted_<filename>.
    Returns a JSON summary of the file metadata.
    """
    print("\n" + "-"*60)
    print("[BLOCK] File Extraction & Hash Request")
    print(f"[ACTION] Extracting file from E01: {file_path}")
    
    file_path = file_path.strip().strip('"').strip("'")
    if not file_path:
        return json.dumps({"status": "failed", "error": "Empty file path provided."})
        
    e01_path = DEFAULT_E01_PATH
    if not os.path.exists(e01_path):
        return json.dumps({"status": "failed", "error": f"E01 disk image not found at: {e01_path}"})
        
    dir_parts, filename = parse_windows_path(file_path)
    if not filename:
        return json.dumps({"status": "failed", "error": "Could not extract filename from path."})
        
    print(f"    ├── Directory parts: {dir_parts}")
    print(f"    ├── Target filename: {filename}")
    
    if dir_parts:
        print(f"    ├── Resolving directory path node...")
        dir_node = resolve_node_for_path_parts(e01_path, dir_parts)
        if not dir_node:
            print(f"[STATUS] [FAILED] Could not resolve directory path parts in E01.")
            print("-" * 60)
            return json.dumps({"status": "failed", "error": f"Could not resolve directory path parts in E01: {dir_parts}"})
    else:
        dir_node = ""
        
    print(f"    ├── Directory node resolved to: {dir_node or 'Root'}")
    
    cmd = ["fls", "-i", "ewf", e01_path]
    if dir_node:
        cmd.append(dir_node)
        
    fls_proc = subprocess.run(cmd, capture_output=True, text=True)
    if fls_proc.returncode != 0:
        print(f"[STATUS] [FAILED] fls failed on node {dir_node or 'Root'}")
        print("-" * 60)
        return json.dumps({"status": "failed", "error": f"fls command failed: {fls_proc.stderr}"})
        
    file_node = None
    for line in fls_proc.stdout.splitlines():
        match = re.search(r'^[a-zA-Z]/[a-zA-Z]\s+[\*]?\s*(\d+)(?:-\d+-\d+)?:\s+(.*)$', line.strip())
        if match:
            node_str = match.group(1)
            name = match.group(2).strip()
            if name.lower() == filename.lower():
                file_node = node_str
                break
                
    if not file_node:
        print(f"[STATUS] [FAILED] File '{filename}' not found under directory node '{dir_node or 'Root'}'")
        print("-" * 60)
        dir_path_str = '\\'.join(dir_parts)
        return json.dumps({"status": "failed", "error": f"File '{filename}' not found in directory '{dir_path_str}'."})
        
    print(f"    ├── File node resolved to: {file_node}")
    print(f"    ├── Extracting and hashing via icat...")
    
    import hashlib
    sha256 = hashlib.sha256()
    size = 0
    dest_path = f"/mnt/sift_ext4/extracted_{filename}"
    
    icat_cmd = ["icat", "-i", "ewf", e01_path, file_node]
    proc = subprocess.Popen(icat_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    try:
        with open(dest_path, "wb") as f_out:
            while True:
                chunk = proc.stdout.read(65536)
                if not chunk:
                    break
                sha256.update(chunk)
                size += len(chunk)
                f_out.write(chunk)
    except Exception as e:
        proc.kill()
        if os.path.exists(dest_path):
            os.remove(dest_path)
        print(f"[STATUS] [FAILED] File write error: {str(e)}")
        print("-" * 60)
        return json.dumps({"status": "failed", "error": f"Error writing extracted file: {str(e)}"})
        
    proc.wait()
    stderr_output = proc.stderr.read().decode('utf-8', errors='ignore')
    proc.stderr.close()
    
    if proc.returncode != 0:
        if os.path.exists(dest_path):
            os.remove(dest_path)
        print(f"[STATUS] [FAILED] icat failed: {stderr_output}")
        print("-" * 60)
        return json.dumps({"status": "failed", "error": f"icat command failed: {stderr_output}"})
        
    sha256_hash = sha256.hexdigest()
    print(f"[STATUS] [SUCCESS] File extracted to: {dest_path}")
    print(f"    ├── Size: {size} bytes")
    print(f"    └── SHA-256: {sha256_hash}")
    print("-" * 60)
    
    return json.dumps({
        "status": "success",
        "filename": filename,
        "inode": file_node,
        "sha256": sha256_hash,
        "size": size,
        "extracted_path": dest_path
    }, indent=2)

# --- CLI INTERFACE ---

def main():
    print(f"\n[{'='*60}]")
    print("[ PROJECT FIND EVIL - AUTONOMOUS ORCHESTRATOR V2.0 ]")
    print(f"[{'='*60}]\n")
    
    # Initialize thoughts log
    try:
        with open("thoughts.txt", "w") as f:
            f.write("=== PROJECT FIND EVIL: AGENT COGNITIVE LOG ===\n\n")
    except Exception as e:
        print(f"[!] Failed to initialize thoughts.txt: {e}")
        sys.exit(1)
        
    print("[*] CLI initialized successfully.")
    print("Commands:")
    print("  investigate : Run automated 3-phase triage & analyze anomalies.")
    print("  exit        : Close the session.")
    print("=" * 62)

    while True:
        try:
            user_input = input("\n[Investigator] > ")
            
            if user_input.lower() in ['exit', 'quit']:
                print("\n[*] Terminating session.")
                break
                
            if not user_input.strip():
                continue

            if user_input.lower() == 'investigate':
                # Run the automated triage pipeline
                run_automation_engine(DEFAULT_IMAGE_PATH, DEFAULT_E01_PATH, DEFAULT_PROFILE_PATH)
                
                # Initialize autonomous agent
                print("[*] Initializing autonomous analyzer agent...")
                try:
                    agent_system = FindEvilAgent()
                    chat_session = agent_system.create_session(
                        tools_list=[record_cognitive_process, query_triage_profile, test_live_mcp_connection, extract_and_hash_by_path]
                    )
                except Exception as e:
                    print(f"[!] Failed to start agent: {e}")
                    continue
                
                agent_prompt = (
                    "Triage data is collected. Retrieve the triage profile using `query_triage_profile`. "
                    "Analyze the flagged processes, malfind memory regions, and directory listings. "
                    "To detect potential DLL sideloading, you MUST query the directory of `Teams.exe`, extract and hash "
                    "multiple local `api-ms-win-core-*.dll` files using the `extract_and_hash_by_path` tool, and "
                    "compare their SHA-256 hashes to find any mismatched DLLs. Output your final triage report."
                )
                
                print("\n[Agent is analyzing triage telemetry...]")
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        response = chat_session.send_message(agent_prompt)
                        
                        print(f"\n[{'='*60}]")
                        print("[ FINAL TRIAGE REPORT ]")
                        print(f"[{'='*60}]")
                        print(response.text)
                        break
                        
                    except Exception as e:
                        error_msg = str(e)
                        if '503' in error_msg or 'UNAVAILABLE' in error_msg:
                            if attempt < max_retries - 1:
                                print(f"    [!] 503 Server Unavailable. Retrying in 12 seconds... (Attempt {attempt + 1}/{max_retries})")
                                time.sleep(12)
                            else:
                                print(f"\n[!] Agent Error: Google API servers are overloaded. Please try again later.")
                        elif '429' in error_msg or 'RESOURCE_EXHAUSTED' in error_msg or 'quota' in error_msg.lower():
                            if attempt < max_retries - 1:
                                print(f"    [!] 429 Rate Limit / Quota Exceeded. Retrying in 30 seconds... (Attempt {attempt + 1}/{max_retries})")
                                time.sleep(30)
                            else:
                                print(f"\n[!] Agent Error: Rate limit or quota exceeded. Please check your plan details and try again later.")
                        else:
                            raise e
            else:
                # Standard chat mode for follow-up questions
                print("\n[Agent is processing question...]")
                # We need to make sure chat_session is initialized
                if 'chat_session' not in locals():
                    print("[!] Please run 'investigate' first to initialize the forensic environment.")
                    continue
                    
                response = chat_session.send_message(user_input)
                print(f"\n[Agent Response]:\n{response.text}")
            
        except EOFError:
            print("\n[*] Session ended (EOF/Pipe).")
            break
        except KeyboardInterrupt:
            print("\n\n[*] Manual interrupt detected. Terminating session.")
            break
        except Exception as e:
            print(f"\n[!] Orchestrator Error: {str(e)}")

if __name__ == "__main__":
    main()
