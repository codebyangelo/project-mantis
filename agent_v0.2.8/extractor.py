import os
import subprocess
import json
import re
import time
import argparse
from config import EVIDENCE_DIR, CACHE_DIR
from logger import ExecutionLogger

def classify_image(file_path):
    """
    Classifies raw files natively by inspecting block headers and extensions.
    """
    # 1. Manifest override
    manifest_path = os.path.join(EVIDENCE_DIR, "manifest.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r") as f:
                manifest = json.load(f)
                file_name = os.path.basename(file_path)
                if file_name in manifest:
                    return manifest[file_name].lower()
        except Exception as e:
            ExecutionLogger.log("EXTRACTOR", f"Failed to read manifest.json: {e}", "WARN")

    # 2. Extension checks
    ext = os.path.splitext(file_path)[1].lower()
    if ext in ['.mem', '.raw', '.vmem', '.dmp']:
        return "memory"
    if ext in ['.e01', '.qcow2', '.vmdk', '.vhdx']:
        return "disk"
        
    # 3. Native byte inspection for ambiguous .dd files
    if ext in ['.dd', '.img']:
        try:
            with open(file_path, 'rb') as f:
                # Check for MBR signature at byte 510
                f.seek(510)
                mbr_sig = f.read(2)
                if mbr_sig == b'\x55\xaa':
                    return "disk"
                
                # Check for GPT signature at byte 512
                f.seek(512)
                gpt_sig = f.read(8)
                if gpt_sig == b'EFI PART':
                    return "disk"
                    
                # No block-level signatures found, assume memory
                return "memory"
        except IOError:
            ExecutionLogger.log("EXTRACTOR", f"Error reading file headers for {file_path}. Defaulting to memory.", "WARN")
            return "memory"
            
    return None

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

def parse_and_cache(raw_json, cache_name, image_path):
    # Unique name
    base_name = os.path.splitext(os.path.basename(image_path))[0]
    safe_base = re.sub(r'[^A-Za-z0-9_\-]', '_', base_name)
    unique_cache_name = f"{cache_name}_{safe_base}"
    
    unique_path = os.path.join(CACHE_DIR, f"{unique_cache_name}.json")
    aggregate_path = os.path.join(CACHE_DIR, f"{cache_name}.json")
    
    try:
        data = json.loads(raw_json)
        
        # Write unique cache
        with open(unique_path, "w") as f:
            json.dump(data, f, indent=4)
        ExecutionLogger.log("EXTRACTOR", f"Cached {unique_cache_name} data to {unique_path}", "SUCCESS")
        
        # Aggregate cache for backward compatibility (sieve.py relies on standard names)
        aggregate_data = []
        if os.path.exists(aggregate_path):
            try:
                with open(aggregate_path, "r") as f:
                    aggregate_data = json.load(f)
            except Exception:
                pass
        
        if isinstance(data, list):
            aggregate_data.extend(data)
        elif isinstance(data, dict):
            if isinstance(aggregate_data, list):
                aggregate_data.append(data)
            else:
                aggregate_data.update(data)
                
        with open(aggregate_path, "w") as f:
            json.dump(aggregate_data, f, indent=4)
            
    except Exception as e:
        ExecutionLogger.log("EXTRACTOR", f"Failed to cache {cache_name} for {image_path}: {e}", "WARN")

def extract_pstree(memory_image):
    out = run_plugin(memory_image, "pstree")
    parse_and_cache(out, "pstree", memory_image)

def extract_cmdline(memory_image):
    out = run_plugin(memory_image, "cmdline")
    parse_and_cache(out, "cmdline", memory_image)

def extract_malfind(memory_image):
    out = run_plugin(memory_image, "malfind")
    parse_and_cache(out, "malfind", memory_image)

def extract_netscan(memory_image):
    out = run_plugin(memory_image, "netscan")
    parse_and_cache(out, "netscan", memory_image)

def extract_hivelist(memory_image):
    out = run_plugin(memory_image, "registry.hivelist")
    parse_and_cache(out, "hivelist", memory_image)

def prcarve_registry_map(disk_image_path):
    """Parses fls bodyfile to locate critical registry hives for physical extraction."""
    ExecutionLogger.log("EXTRACTOR", f"Initiating registry map generation via FLS bodyfile parsing for {disk_image_path}.")
    
    base_name = os.path.splitext(os.path.basename(disk_image_path))[0]
    safe_base = re.sub(r'[^A-Za-z0-9_\-]', '_', base_name)
    
    bodyfile_path = os.path.join(CACHE_DIR, f"bodyfile_{safe_base}.txt")
    if not os.path.exists(bodyfile_path):
        ExecutionLogger.log("EXTRACTOR", "Bodyfile missing. Attempting to generate...")
        generate_bodyfile(disk_image_path, bodyfile_path)
        
    if not os.path.exists(bodyfile_path):
        ExecutionLogger.log("EXTRACTOR", f"Failed to locate bodyfile for registry carve on {disk_image_path}.", "ERROR")
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
                            "inode": inode,
                            "source_image": disk_image_path
                        })
    
    # Write unique registry map
    unique_map_path = os.path.join(CACHE_DIR, f"registry_map_{safe_base}.json")
    with open(unique_map_path, "w") as f:
        json.dump(found, f, indent=4)
        
    # Aggregate into global registry map
    global_map_path = os.path.join(CACHE_DIR, "registry_map.json")
    global_found = {"SYSTEM": [], "SOFTWARE": [], "NTUSER": []}
    if os.path.exists(global_map_path):
        try:
            with open(global_map_path, "r") as f:
                global_found = json.load(f)
        except Exception:
            pass
            
    for key in found:
        if key in global_found:
            global_found[key].extend(found[key])
        else:
            global_found[key] = found[key]
            
    with open(global_map_path, "w") as f:
        json.dump(global_found, f, indent=4)
        
    count = sum(len(v) for v in found.values())
    ExecutionLogger.log("EXTRACTOR", f"Registry mapping complete for {disk_image_path}. Discovered {count} target hives.", "SUCCESS")

def detect_partition_offset(disk_image_path):
    ExecutionLogger.log("EXTRACTOR", f"Detecting partition offset via mmls on {disk_image_path}...")
    try:
        out = subprocess.check_output(["mmls", disk_image_path], text=True)
        largest_offset = None
        max_length = 0
        
        for line in out.splitlines():
            if "NTFS" in line or "Basic data partition" in line:
                parts = line.split()
                numbers = [p for p in parts if p.isdigit()]
                if len(numbers) >= 3:
                    # start is numbers[-3], end is numbers[-2], length is numbers[-1]
                    start_offset = int(numbers[-3])
                    length = int(numbers[-1])
                    if length > max_length:
                        max_length = length
                        largest_offset = str(start_offset)
                        
        if largest_offset:
            ExecutionLogger.log("EXTRACTOR", f"Largest NTFS partition offset detected: {largest_offset} (Length: {max_length})", "SUCCESS")
            return largest_offset
            
    except Exception as e:
        ExecutionLogger.log("EXTRACTOR", f"mmls failed: {e}. Falling back to default offset 0.", "WARN")
    return None

def generate_bodyfile(disk_image_path, output_path):
    """Dynamically generates bodyfile.txt using fls."""
    ExecutionLogger.log("EXTRACTOR", f"Generating bodyfile via fls for {disk_image_path}...")
    
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

def carve_and_stream_strings(disk_image_path, inode, output_name, keywords):
    """
    Ingenuity: Uses icat to stream file contents directly, extracting ASCII and UTF-16 strings
    matching specific keywords without holding the binary in memory.
    """
    offset = detect_partition_offset(disk_image_path)
    cmd = ["icat"]
    if offset:
        cmd.extend(["-o", str(offset)])
    cmd.extend([disk_image_path, inode])
    
    hits = []
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        
        # Read in 1MB chunks to respect the 1.3GB RAM limit
        chunk_size = 1024 * 1024
        buffer_ascii = ""
        buffer_utf16 = ""
        
        while True:
            chunk = proc.stdout.read(chunk_size)
            if not chunk:
                break
                
            for i in range(len(chunk)):
                c = chunk[i]
                
                # ASCII Carving
                if 32 <= c <= 126:
                    buffer_ascii += chr(c)
                else:
                    if len(buffer_ascii) >= 4:
                        lower_str = buffer_ascii.lower()
                        for kw in keywords:
                            if kw in lower_str:
                                hits.append(buffer_ascii)
                                break
                    buffer_ascii = ""
                    
                # Basic UTF-16LE Carving
                if i % 2 == 0 and i + 1 < len(chunk):
                    c1, c2 = chunk[i], chunk[i+1]
                    if c2 == 0 and 32 <= c1 <= 126:
                        buffer_utf16 += chr(c1)
                    else:
                        if len(buffer_utf16) >= 4:
                            lower_str = buffer_utf16.lower()
                            for kw in keywords:
                                if kw in lower_str:
                                    hits.append(buffer_utf16)
                                    break
                        buffer_utf16 = ""
                        
    except Exception as e:
        ExecutionLogger.log("EXTRACTOR", f"Streaming failed for {output_name}: {e}", "WARN")
        
    return list(set(hits)) # Unique hits

def extract_evtx_stream(disk_image_path):
    ExecutionLogger.log("EXTRACTOR", f"[DEEP MODE] Streaming Windows Event Logs from {disk_image_path}...")
    base_name = os.path.splitext(os.path.basename(disk_image_path))[0]
    safe_base = re.sub(r'[^A-Za-z0-9_\-]', '_', base_name)
    bodyfile_path = os.path.join(CACHE_DIR, f"bodyfile_{safe_base}.txt")
    
    if not os.path.exists(bodyfile_path):
        return

    evtx_keywords = ["powershell", "cmd.exe", "whoami", "mimikatz", "admin", "logon", "rdp"]
    evtx_hits = {}
    
    with open(bodyfile_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "winevt/Logs/Security.evtx" in line or "winevt/Logs/System.evtx" in line:
                parts = line.split('|')
                if len(parts) > 3:
                    inode = parts[2].split('-')[0]
                    name = parts[1].split('/')[-1]
                    ExecutionLogger.log("EXTRACTOR", f"Streaming {name} (Inode: {inode})...")
                    hits = carve_and_stream_strings(disk_image_path, inode, name, evtx_keywords)
                    if hits:
                        evtx_hits[name] = hits

    if evtx_hits:
        cache_path = os.path.join(CACHE_DIR, f"evtx_stream_{safe_base}.json")
        with open(cache_path, "w") as f:
            json.dump(evtx_hits, f, indent=4)
        ExecutionLogger.log("EXTRACTOR", "EVTX streaming to cache complete.", "SUCCESS")

def extract_prefetch_stream(disk_image_path):
    ExecutionLogger.log("EXTRACTOR", f"[DEEP MODE] Streaming Prefetch parsing from {disk_image_path}...")
    base_name = os.path.splitext(os.path.basename(disk_image_path))[0]
    safe_base = re.sub(r'[^A-Za-z0-9_\-]', '_', base_name)
    bodyfile_path = os.path.join(CACHE_DIR, f"bodyfile_{safe_base}.txt")
    
    if not os.path.exists(bodyfile_path):
        return

    pf_keywords = [".exe", "temp", "appdata", "powershell", "cmd"]
    pf_hits = {}
    
    with open(bodyfile_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "/Prefetch/" in line and line.lower().endswith(".pf|"):
                parts = line.split('|')
                if len(parts) > 3:
                    inode = parts[2].split('-')[0]
                    name = parts[1].split('/')[-1]
                    hits = carve_and_stream_strings(disk_image_path, inode, name, pf_keywords)
                    if hits:
                        pf_hits[name] = hits

    if pf_hits:
        cache_path = os.path.join(CACHE_DIR, f"prefetch_stream_{safe_base}.json")
        with open(cache_path, "w") as f:
            json.dump(pf_hits, f, indent=4)
        ExecutionLogger.log("EXTRACTOR", "Prefetch streaming to cache complete.", "SUCCESS")

def main():
    parser = argparse.ArgumentParser(description="Mantis Extractor")
    parser.add_argument("--deep", action="store_true", help="Enable deep forensics extraction (EVTX, Prefetch, streaming parsing)")
    args = parser.parse_args()

    ExecutionLogger.log("EXTRACTOR", "Initializing Forensic Extractor Component...")
    
    # Ensure fresh aggregate files for new run
    for agg_file in ["pstree.json", "cmdline.json", "malfind.json", "netscan.json", "hivelist.json", "registry_map.json", "context.json"]:
        agg_path = os.path.join(CACHE_DIR, agg_file)
        if os.path.exists(agg_path):
            os.remove(agg_path)
    
    mem_images = []
    disk_images = []
    
    for f in os.listdir(EVIDENCE_DIR):
        file_path = os.path.join(EVIDENCE_DIR, f)
        if not os.path.isfile(file_path):
            continue
            
        img_type = classify_image(file_path)
        if img_type == "memory":
            mem_images.append(file_path)
        elif img_type == "disk":
            disk_images.append(file_path)
        else:
            ExecutionLogger.log("EXTRACTOR", f"Skipping unclassified file: {f}", "WARN")
                
    if not mem_images:
        ExecutionLogger.log("EXTRACTOR", "No memory images found in evidence directory.", "WARN")
    if not disk_images:
        ExecutionLogger.log("EXTRACTOR", "No disk images found in evidence directory.", "WARN")
        
    context = {
        "Investigation_ID": "PFE-AUTOGEN",
        "Evidence_Files": {
            "Memory": mem_images[0] if mem_images else "",
            "Disk_Image": disk_images[0] if disk_images else "",
            "Memory_Images": mem_images,
            "Disk_Images": disk_images
        },
        "Cache_Status": "BUILT"
    }
    
    ctx_path = os.path.join(CACHE_DIR, "context.json")
    with open(ctx_path, "w") as f:
        json.dump(context, f, indent=4)
        
    for mem_image in mem_images:
        ExecutionLogger.log("EXTRACTOR", f"Commencing memory triage plugin execution on {mem_image}...")
        extract_pstree(mem_image)
        extract_cmdline(mem_image)
        extract_malfind(mem_image)
        extract_netscan(mem_image)
        
    for disk_image in disk_images:
        ExecutionLogger.log("EXTRACTOR", f"Commencing physical disk metadata extraction on {disk_image}...")
        prcarve_registry_map(disk_image)
        if args.deep:
            extract_evtx_stream(disk_image)
            extract_prefetch_stream(disk_image)
            
    ExecutionLogger.log("EXTRACTOR", "Extraction Phase Complete.", "SUCCESS")

if __name__ == "__main__":
    main()
