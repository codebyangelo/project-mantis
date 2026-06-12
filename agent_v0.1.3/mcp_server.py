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
    print(f"\n[TOOL START] Executing query_json_cache(cache='{cache_name}', keyword='{keyword}')")
    time.sleep(1) # Micro-jitter
    filepath = os.path.join(CACHE_DIR, f"{cache_name}.json")

    if not os.path.exists(filepath):
        return f"[!] Cache for {cache_name} not found."

    try:
        # --- NATIVE MALFIND PARSER ---
        if cache_name == "malfind" and keyword == "PAGE_EXECUTE_READWRITE":
            try:
                cmd = f"grep -B 5 -i 'PAGE_EXECUTE_READWRITE' {filepath} | grep -i 'PID' | grep -oP '\\d+'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                pids = list(set(result.stdout.strip().split('\n')))
                pids = [p for p in pids if p] 
                
                if not pids:
                    return "[*] No PAGE_EXECUTE_READWRITE segments found."
                return f"[*] Identified PIDs with PAGE_EXECUTE_READWRITE segments: {', '.join(pids)}\n[DIRECTIVE] You MUST iterate through these PIDs one by one."
            except Exception:
                pass 
        # ----------------------------------

        # If no keyword, return raw
        if not keyword:
            with open(filepath, "r") as f:
                data = f.read()
                if len(data) > 50000:
                    return f"[!] SYSTEM DENIAL: Payload too large. Use a keyword (like a PID) to filter {cache_name}."
                return data

        # ZERO-DEPENDENCY NATIVE PARSING
        # Bypasses brittle 'jq' schema assumptions. Volatility nests JSON deeply; grep extracts it regardless of depth.
        cmd = f"grep -i -C 15 '{keyword}' {filepath}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        output = result.stdout.strip()
        if not output:
            return f"[*] Keyword '{keyword}' not found in {cache_name}."

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
    # Autonomous override for network routing telemetry
    if regex_pattern == "NETWORK" or "http" in regex_pattern.lower():
        task_name = "Carving Memory for: Strict Routable IPv4"
        
        # PCRE regex for strict 0-255 IPv4 boundaries
        strict_ipv4 = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        
        # ERE regex for RFC 1918, Loopback, and Broadcast filtering
        rfc_1918_filter = r"^(10\.|192\.168\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|255\.255\.|0\.0\.)"
        
        # Pipeline execution
        cmd = (
            f"strings -a {memory_image_path} | "
            f"grep -oP '{strict_ipv4}' | "
            f"grep -vE '{rfc_1918_filter}' | "
            f"sort -u | head -n 30"
        )
    else:
        task_name = f"Carving Memory for: '{regex_pattern}'"
        cmd = (
            f"strings -a {memory_image_path} | "
            f"grep -iE '{regex_pattern}' | "
            f"grep -v 'microsoft' | sort -u | head -n 30"
        )

    try:
        # Use the timer wrapper from mcp_server
        output = run_with_timer(cmd, task_name)
        return output if output.strip() else "[*] NULL HYPOTHESIS MET: No external routable indicators found."
    except Exception as e:
        return f"[!] MEMORY CARVE ERROR: {e}"

def read_dfir_playbook() -> str:
    path = "/mnt/sift_ext4/dfir_playbook.json"
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read()
    return "Playbook not found."
