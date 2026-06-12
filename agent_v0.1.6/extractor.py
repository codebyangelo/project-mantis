import os
import subprocess
import json
import re
import time
from config import EVIDENCE_DIR, CACHE_DIR
from logger import ExecutionLogger

def run_plugin(image_path, plugin, args=[]):
    ExecutionLogger.log("EXTRACTOR", f"Executing windows.{plugin} on {image_path}...")
    cmd = ["vol", "-f", image_path, "-r", "json", f"windows.{plugin}"] + args
    start = time.time()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
        ExecutionLogger.log("EXTRACTOR", f"Plugin {plugin} completed in {time.time() - start:.2f}s", "SUCCESS")
        return result.stdout
    except subprocess.TimeoutExpired:
        ExecutionLogger.log("EXTRACTOR", f"Timeout in {plugin} after 300s", "ERROR")
        return f'{{"EXECUTION_ERROR": "TimeoutExpired"}}'
    except subprocess.CalledProcessError as e:
        ExecutionLogger.log("EXTRACTOR", f"Error in {plugin}: {e}", "ERROR")
        return f'{{"EXECUTION_ERROR": "{e}"}}'

def parse_and_cache(raw_json, cache_name):
    cache_path = os.path.join(CACHE_DIR, f"{cache_name}.json")
    try:
        data = json.loads(raw_json)
        with open(cache_path, "w") as f:
            json.dump(data, f, indent=4)
        ExecutionLogger.log("EXTRACTOR", f"Cached {cache_name} data to {cache_path}", "SUCCESS")
    except Exception as e:
        ExecutionLogger.log("EXTRACTOR", f"Failed to cache {cache_name}: {e}", "WARN")

def extract_pstree(memory_image):
    out = run_plugin(memory_image, "pstree")
    parse_and_cache(out, "pstree")

def extract_cmdline(memory_image):
    out = run_plugin(memory_image, "cmdline")
    parse_and_cache(out, "cmdline")

def extract_malfind(memory_image):
    out = run_plugin(memory_image, "malfind")
    parse_and_cache(out, "malfind")

def extract_netscan(memory_image):
    out = run_plugin(memory_image, "netscan")
    parse_and_cache(out, "netscan")

def extract_hivelist(memory_image):
    out = run_plugin(memory_image, "registry.hivelist")
    parse_and_cache(out, "hivelist")

def prcarve_registry_map(disk_image_path):
    """Parses fls bodyfile to locate critical registry hives for physical extraction."""
    ExecutionLogger.log("EXTRACTOR", "Initiating registry map generation via FLS bodyfile parsing.")
    bodyfile_path = os.path.join(CACHE_DIR, "bodyfile.txt")
    if not os.path.exists(bodyfile_path):
        ExecutionLogger.log("EXTRACTOR", "Bodyfile missing. Attempting to generate...")
        generate_bodyfile(disk_image_path)
        
    if not os.path.exists(bodyfile_path):
        ExecutionLogger.log("EXTRACTOR", "Failed to locate bodyfile.txt for registry carve.", "ERROR")
        return

    targets = {
        "SYSTEM": r"Windows/System32/config/SYSTEM\|",
        "SOFTWARE": r"Windows/System32/config/SOFTWARE\|",
        "NTUSER": r"Users/[^/]+/NTUSER\.DAT\|"
    }
    
    exclude = re.compile(r"/(default|public|Windows\.old)/", re.IGNORECASE)
    
    found = {"SYSTEM": [], "SOFTWARE": [], "NTUSER": []}
    
    ExecutionLogger.log("EXTRACTOR", "Streaming bodyfile lines through regex filters...")
    with open(bodyfile_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if exclude.search(line):
                continue
            for key, pattern in targets.items():
                if re.search(pattern, line, re.IGNORECASE):
                    parts = line.split('|')
                    if len(parts) > 3:
                        inode_full = parts[2]
                        inode = inode_full.split('-')[0]
                        found[key].append({
                            "path": parts[1],
                            "inode_full": inode_full,
                            "inode": inode
                        })
    
    cache_path = os.path.join(CACHE_DIR, "registry_map.json")
    with open(cache_path, "w") as f:
        json.dump(found, f, indent=4)
        
    count = sum(len(v) for v in found.values())
    ExecutionLogger.log("EXTRACTOR", f"Registry mapping complete. Discovered {count} target hives.", "SUCCESS")

def detect_partition_offset(disk_image_path):
    ExecutionLogger.log("EXTRACTOR", f"Detecting partition offset via mmls on {disk_image_path}...")
    try:
        out = subprocess.check_output(["mmls", disk_image_path], text=True)
        for line in out.splitlines():
            if "NTFS" in line or "Basic data partition" in line:
                parts = line.split()
                for p in parts:
                    if p.isdigit() and int(p) > 100:
                        ExecutionLogger.log("EXTRACTOR", f"Partition offset detected: {p}", "SUCCESS")
                        return p
    except Exception as e:
        ExecutionLogger.log("EXTRACTOR", f"mmls failed: {e}. Falling back to default offset 0.", "WARN")
    return None

def generate_bodyfile(disk_image_path):
    """Dynamically generates bodyfile.txt using fls."""
    ExecutionLogger.log("EXTRACTOR", "Generating bodyfile via fls...")
    output_path = os.path.join(CACHE_DIR, "bodyfile.txt")
    
    offset = detect_partition_offset(disk_image_path)
    if offset:
        cmd = ["fls", "-o", str(offset), "-r", "-m", "/", disk_image_path]
    else:
        cmd = ["fls", "-r", "-m", "/", disk_image_path]
        
    start = time.time()
    try:
        with open(output_path, "w") as f:
            subprocess.run(cmd, stdout=f, check=True, timeout=300)
        ExecutionLogger.log("EXTRACTOR", f"FLS extraction complete. Bodyfile created in {time.time() - start:.2f}s.", "SUCCESS")
        return output_path
    except subprocess.CalledProcessError as e:
        ExecutionLogger.log("EXTRACTOR", f"FLS failed: {e}", "ERROR")
        return None

def main():
    ExecutionLogger.log("EXTRACTOR", "Initializing Forensic Extractor Component...")
    
    # Locate evidence
    mem_image = None
    disk_image = None
    
    for f in os.listdir(EVIDENCE_DIR):
        if f.endswith(('.raw', '.mem', '.img', '.vmem')):
            mem_image = os.path.join(EVIDENCE_DIR, f)
        elif f.endswith(('.E01', '.dd', '.img', '.vhdx')):
            if "mem" not in f.lower():
                disk_image = os.path.join(EVIDENCE_DIR, f)
                
    if not mem_image:
        ExecutionLogger.log("EXTRACTOR", "No memory image found in evidence directory.", "WARN")
    if not disk_image:
        ExecutionLogger.log("EXTRACTOR", "No disk image found in evidence directory.", "WARN")
        
    context = {
        "Investigation_ID": "PFE-AUTOGEN",
        "Evidence_Files": {
            "Memory": mem_image,
            "Disk_Image": disk_image
        },
        "Cache_Status": "BUILT"
    }
    
    ctx_path = os.path.join(CACHE_DIR, "context.json")
    with open(ctx_path, "w") as f:
        json.dump(context, f, indent=4)
        
    if mem_image:
        ExecutionLogger.log("EXTRACTOR", "Commencing memory triage plugin execution...")
        extract_pstree(mem_image)
        extract_cmdline(mem_image)
        extract_malfind(mem_image)
        extract_netscan(mem_image)
        
    if disk_image:
        ExecutionLogger.log("EXTRACTOR", "Commencing physical disk metadata extraction...")
        prcarve_registry_map(disk_image)
        
    ExecutionLogger.log("EXTRACTOR", "Extraction Phase Complete.", "SUCCESS")

if __name__ == "__main__":
    main()
