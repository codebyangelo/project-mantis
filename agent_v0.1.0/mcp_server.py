import subprocess
import os
import json
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.path.join(BASE_DIR, "evidence_cache")

def read_evidence_cache(plugin_name: str, keyword: str = "") -> str:
    """Reads Volatility output with absolute telemetry and asymmetric payload limits."""
    print(f"\n[TOOL START] Executing read_evidence_cache(plugin='{plugin_name}', keyword='{keyword}')")
    print(f"[*] API Governor: Enforcing 5-second cadence to protect RPM quota...")
    time.sleep(5) 

    json_path = os.path.join(CACHE_DIR, f"{plugin_name}.json")
    txt_path = os.path.join(CACHE_DIR, f"{plugin_name}.txt")
    filepath = txt_path if os.path.exists(txt_path) else json_path

    if not os.path.exists(filepath):
        print(f"[TOOL FAIL] Cache not found for {plugin_name}.")
        return f"[!] Cache for {plugin_name} not found."

    try:
        with open(filepath, "r") as f:
            if not keyword:
                data = f.read()
                print(f"[*] Raw data read: {len(data)} characters.")
                
                if "netscan" in plugin_name or "malfind" in plugin_name:
                    if len(data) > 50000:
                        msg = (f"[!] SYSTEM DENIAL: '{plugin_name}' is a massive pool scan ({len(data)} chars). "
                               f"Extract PIDs from pstree first, then use the 'keyword' parameter.")
                        print(f"[TOOL FAIL] Payload rejected. Too large.")
                        return msg
                elif len(data) > 300000:
                    print(f"[TOOL FAIL] Map payload exceeds hard cap.")
                    return f"[!] FATAL: {plugin_name} exceeds absolute contextual limits."
                    
                print(f"[TOOL SUCCESS] Returning {len(data)} characters to Agent.")
                return data
            else:
                matched_lines = [line.strip() for line in f if keyword.lower() in line.lower()]
                if not matched_lines:
                    print(f"[TOOL SUCCESS] Keyword '{keyword}' returned 0 matches.")
                    return f"[*] No matches found for keyword '{keyword}' in {plugin_name}."
                
                result = "\n".join(matched_lines)
                if len(result) > 50000:
                    print(f"[TOOL FAIL] Keyword search too broad ({len(result)} chars).")
                    return f"[!] SYSTEM DENIAL: Keyword '{keyword}' is too broad. Narrow your target."
                
                print(f"[TOOL SUCCESS] Returning {len(result)} characters to Agent.")
                return result
    except Exception as e:
        print(f"[TOOL FAIL] Exception: {e}")
        return f"[!] Error parsing cache: {e}"

def read_dfir_playbook() -> str:
    print(f"\n[TOOL START] Executing read_dfir_playbook()")
    time.sleep(2)
    path = "/mnt/sift_ext4/dfir_playbook.json"
    if os.path.exists(path):
        with open(path, "r") as f:
            data = f.read()
            print(f"[TOOL SUCCESS] Playbook loaded ({len(data)} chars).")
            return data
    print(f"[TOOL FAIL] Playbook not found at {path}.")
    return "Playbook not found."

def initiate_global_extraction() -> str:
    """Executes physical OS-level asynchronous extraction."""
    try:
        # Assuming you have an extraction script or you are calling your extractor.py natively.
        # This Popen call fires it asynchronously to protect the N4020 CPU choke point.
        script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "extractor.py")
        subprocess.Popen(
            ["python3", script_path, "--deep"], 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        return "[SYSTEM_STATE_CHANGE] Global extraction initiated via physical OS subprocess. Caches building asynchronously."
    except Exception as e:
        return f"CRITICAL SUBPROCESS ERROR: {e}"

def extract_and_hash_inode(inode: str) -> str:
    """Executes a physical cryptographic hash of the extracted artifact."""
    try:
        # Replace with your actual physical dump directory path
        target_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence_cache", inode)
        
        if not os.path.exists(target_file):
            return f"ERROR: Artifact for inode {inode} not found on disk. Extraction may still be processing."
            
        result = subprocess.run(
            ["sha256sum", target_file], 
            capture_output=True, text=True, check=True
        )
        hash_value = result.stdout.strip().split()[0]
        return f"INODE HASH VERIFIED: {hash_value} for artifact {inode}"
        
    except subprocess.CalledProcessError as e:
        return f"SUBPROCESS ERROR (sha256sum failed): {e.stderr}"
