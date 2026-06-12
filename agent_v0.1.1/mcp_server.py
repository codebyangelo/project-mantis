import subprocess
import os
import json
import time
import sys
import threading

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Redirected to match extractor output
CACHE_DIR = "/media/analyst/external_drive/project_data/evidence_cache"

def run_with_timer(cmd: str, task_name: str) -> str:
    """Executes a blocking subprocess while displaying a live timer on the console."""
    print(f"\n[TOOL START] {task_name}. STANDBY.")
    
    # Shared state between threads
    process_state = {"is_running": True, "output": "", "error": None}
    
    def target():
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            process_state["output"] = result.stdout
        except Exception as e:
            process_state["error"] = e
        finally:
            process_state["is_running"] = False

    # Start the heavy I/O in the background
    worker = threading.Thread(target=target)
    worker.start()

    # Main thread: Manage the visual timer
    start_time = time.time()
    try:
        while process_state["is_running"]:
            elapsed = int(time.time() - start_time)
            mins, secs = divmod(elapsed, 60)
            timer_display = f"[*] Execution Time: [{mins:02d}:{secs:02d}]"
            
            # Print and flush on the same line
            sys.stdout.write('\r' + timer_display)
            sys.stdout.flush()
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[!] Timer interrupted by user.")
        # We don't kill the subprocess here to avoid orphaned processes in this simple wrapper, 
        # but the orchestrator will catch it.
        pass
        
    worker.join() # Ensure the thread is completely closed
    
    print("\n[+] Task Complete.") # Move to a new line after the timer finishes
    
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

def query_json_cache(cache_name: str, keyword: str = "") -> str:
    """Queries pre-computed JSON caches (pstree, malfind, cmdline, netscan) natively."""
    print(f"\n[TOOL START] Executing query_json_cache(cache='{cache_name}', keyword='{keyword}')")
    time.sleep(1) # Micro-jitter to protect CPU
    filepath = os.path.join(CACHE_DIR, f"{cache_name}.json")
    
    if not os.path.exists(filepath):
        return f"[!] Cache for {cache_name} not found."
    
    try:
        # If no keyword, return raw (Warning: Could be massive)
        if not keyword:
            with open(filepath, "r") as f:
                data = f.read()
            if len(data) > 50000:
                return f"[!] SYSTEM DENIAL: Payload too large. Use a keyword (like a PID) to filter {cache_name}."
            return data

        # Use native jq for surgical extraction if it's a PID
        if keyword.isdigit() and cache_name in ["pstree", "cmdline", "malfind"]:
            cmd = f"jq -r '.[] | select(.PID == {keyword} or .PPID == {keyword})' {filepath}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout if result.stdout else f"[*] PID {keyword} not found in {cache_name}."
        else:
            # Fallback to grep with context buffer to preserve JSON structure
            cmd = f"grep -i -C 15 '{keyword}' {filepath}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            output = result.stdout.strip()
            if not output:
                return f"[*] Keyword '{keyword}' not found in {cache_name}."
            
            # Protect the context window from massive dumps
            if len(output) > 8000:
                return output[:8000] + "\n\n[!] OUTPUT TRUNCATED: Too many matches. Refine your keyword."
            return output
            
    except Exception as e:
        return f"[!] Error parsing cache: {e}"

def extract_and_carve_hive(inode: str, disk_image_path: str) -> str:
    task_name = f"Physical Hive Extraction & Carve (Inode: {inode})"
    try:
        cmd = (
            f"icat -i ewf {disk_image_path} {inode} | "
            f"strings -el | grep -Fi 'C:\\' | grep -i '\\.dll' | "
            f"grep -ivE 'system32|syswow64|winsxs|program files|microsoft\\.net' | sort -u"
        )
        
        # Use the timer wrapper
        output = run_with_timer(cmd, task_name).strip()
        
        if not output:
            return "[*] HIVE CARVE CLEAN: No anomalous absolute DLL paths found. If memory shows compromise, injection is purely fileless."
        return f"[!] ANOMALY DETECTED IN HIVE:\n{output}"
    except Exception as e:
        return f"[!] HIVE CARVE ERROR: {e}"

def carve_memory_strings(regex_pattern: str, memory_image_path: str) -> str:
    task_name = f"Carving Memory for: '{regex_pattern}'"
    try:
        cmd = f"strings -a {memory_image_path} | grep -iE '{regex_pattern}' | grep -v 'microsoft' | sort -u | head -n 30"
        
        # Use the timer wrapper
        output = run_with_timer(cmd, task_name)
        
        return output if output else "[*] No string matches found."
    except Exception as e:
        return f"[!] MEMORY CARVE ERROR: {e}"

def read_dfir_playbook() -> str:
    path = "/mnt/sift_ext4/dfir_playbook.json"
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read()
    return "Playbook not found."
