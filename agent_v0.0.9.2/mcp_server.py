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

def extract_and_hash_inode(inode: str) -> str:
    print(f"\n[TOOL START] Executing extract_and_hash_inode(inode='{inode}')")
    time.sleep(2)
    print(f"[TOOL SUCCESS] Simulated extraction for {inode}.")
    return f"[SUCCESS] Inode {inode} extracted and hashed (Simulated)."

def initiate_global_extraction() -> str:
    print(f"\n[TOOL START] Executing initiate_global_extraction()")
    print(f"[TOOL SUCCESS] Signal sent.")
    return "[SYSTEM_STATE_CHANGE] INITIATE_HARDWARE_CHOKE"
