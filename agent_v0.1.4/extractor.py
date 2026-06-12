#!/usr/bin/env python3
import subprocess
import json
import os
import argparse
import time
import glob
import struct
from config import EVIDENCE_DIR, CACHE_DIR

def run_plugin(image_path, plugin, args=[]):
    print(f"[*] Executing windows.{plugin}...")
    cmd = ["vol", "-f", image_path, "-r", "json", f"windows.{plugin}"] + args
    start = time.time()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[+] {plugin} complete in {time.time() - start:.2f}s.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[!] Error in {plugin}: {e}")
        return f'{{"EXECUTION_ERROR": "{e}"}}'
    except FileNotFoundError:
        print(f"[!] Volatility binary ('vol') not found. Simulated JSON returned for validation.")
        return f'{{"EXECUTION_ERROR": "vol command not found"}}'

def parse_partition_offset_fallback(disk_image_path):
    """
    Pure Python parser to extract NTFS partition offset from raw MBR/GPT sector.
    Hardens the script against missing 'mmls' binaries.
    """
    print("[*] Running pure Python partition table parser fallback...")
    try:
        with open(disk_image_path, "rb") as f:
            mbr = f.read(512)
            if len(mbr) < 512:
                return None
            
            # Check MBR boot signature
            if mbr[510:512] != b"\x55\xAA":
                return None
            
            # Parse MBR partition table (4 entries of 16 bytes starting at 446)
            is_gpt = False
            for i in range(4):
                part_offset = 446 + (i * 16)
                part_type = mbr[part_offset + 4]
                
                # Type 0xEE is GPT protective MBR
                if part_type == 0xEE:
                    is_gpt = True
                    break
                
                # Type 0x07 is NTFS
                if part_type == 0x07:
                    start_lba = struct.unpack("<I", mbr[part_offset + 8:part_offset + 12])[0]
                    print(f"    [Fallback] Found NTFS MBR partition starting at sector {start_lba}.")
                    return str(start_lba)
            
            # Parse GPT partition table if protective MBR detected
            if is_gpt:
                f.seek(512) # Go to GPT Header (LBA 1)
                gpt_header = f.read(512)
                if len(gpt_header) < 512 or gpt_header[0:8] != b"EFI PART":
                    return None
                
                # Read partition entry details
                entry_lba = struct.unpack("<Q", gpt_header[72:80])[0]
                num_entries = struct.unpack("<I", gpt_header[80:84])[0]
                entry_size = struct.unpack("<I", gpt_header[84:88])[0]
                
                # Go to the partition entries LBA
                f.seek(entry_lba * 512)
                for _ in range(num_entries):
                    entry = f.read(entry_size)
                    if len(entry) < entry_size:
                        break
                    
                    # Read GUID (16 bytes)
                    # Basic Data Partition GUID: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
                    guid = entry[0:16]
                    ntfs_guid = b"\xa2\x0a\xd0\xeb\xe5\xb9\x33\x44\x87\xc0\x68\xb6\xb7\x26\x99\xc7"
                    
                    if guid == ntfs_guid:
                        start_lba = struct.unpack("<Q", entry[32:40])[0]
                        print(f"    [Fallback] Found NTFS GPT partition starting at sector {start_lba}.")
                        return str(start_lba)
                        
    except Exception as e:
        print(f"    [Fallback] Error in Python partition parser: {e}")
    return None

def detect_partition_offset(disk_image_path):
    """Uses native mmls to determine NTFS/Data offset, falling back to pure Python parser."""
    print(f"[*] Analyzing disk geometry: {disk_image_path}")
    try:
        result = subprocess.run(["mmls", disk_image_path], capture_output=True, text=True)
        if result.returncode != 0 or "Cannot determine" in result.stderr:
            # Try Python parser fallback
            return parse_partition_offset_fallback(disk_image_path)
        
        lines = result.stdout.split('\n')
        for line in lines:
            line_upper = line.upper()
            if "NTFS" in line_upper or "BASIC DATA PARTITION" in line_upper:
                parts = line.split()
                if len(parts) > 3 and parts[2].isdigit():
                    offset = parts[2]
                    print(f"[*] Geometry: Partition offset found at sector {offset}.")
                    return offset
                    
        # Try Python fallback if mmls succeeded but didn't identify NTFS
        return parse_partition_offset_fallback(disk_image_path)
    except FileNotFoundError:
        # mmls is missing - run Python parser fallback
        return parse_partition_offset_fallback(disk_image_path)
    except Exception as e:
        print(f"[!] Error in offset detection: {e}")
        return parse_partition_offset_fallback(disk_image_path)

def generate_bodyfile(disk_image_path):
    """Dynamically generates bodyfile.txt using fls."""
    print(f"[*] bodyfile.txt absent. Generating via fls...")
    output_path = os.path.join(CACHE_DIR, "bodyfile.txt")
    
    offset = detect_partition_offset(disk_image_path)
    if offset:
        cmd = f"fls -o {offset} -r -m '/' '{disk_image_path}' > '{output_path}'"
    else:
        cmd = f"fls -r -m '/' '{disk_image_path}' > '{output_path}'"
        
    start = time.time()
    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"[+] FLS extraction complete. bodyfile.txt created in {time.time() - start:.2f}s.")
        return output_path
    except subprocess.CalledProcessError as e:
        print(f"[!] FLS execution failed: {e}")
        return None
    except Exception as e:
         print(f"[!] Error generating bodyfile: {e}")
         return None

def prcarve_registry_map(bodyfile_path):
    """Pre-computes registry inodes to save cognitive/hardware cycles during investigation."""
    print("[*] Pre-carving registry inodes from bodyfile...")
    registry_map = {}
    targets = {
        "SYSTEM": "Windows/System32/config/SYSTEM|",
        "SOFTWARE": "Windows/System32/config/SOFTWARE|",
        "NTUSER": "Users/.*/NTUSER.DAT|"
    }
    
    for key, pattern in targets.items():
        try:
            # Zero-dependency file reading instead of launching subprocess shell command
            inodes = []
            if os.path.exists(bodyfile_path):
                import re
                regex = re.compile(pattern, re.IGNORECASE)
                exclude = re.compile(r"default|public|Windows.old", re.IGNORECASE)
                
                with open(bodyfile_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if regex.search(line) and not exclude.search(line):
                            parts = line.strip().split('|')
                            if len(parts) > 2:
                                inodes.append({"path": parts[1], "inode": parts[2]})
            registry_map[key] = inodes
        except Exception as e:
            print(f"[!] Failed to pre-carve {key}: {e}")
            
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(os.path.join(CACHE_DIR, "registry_map.json"), "w") as f:
        json.dump(registry_map, f, indent=4)
    return registry_map

def build_environment(mode):
    os.makedirs(CACHE_DIR, exist_ok=True)
    state = {}
    context = {"MODE": "UNKNOWN", "Available_Caches": [], "Evidence_Files": {}}

    print("\n" + "="*60)
    print(f"[SYSTEM] Initiating UFE Discovery & Extraction (Mode: {mode.upper()})")
    print(f"[*] Evidence Directory: {EVIDENCE_DIR}")
    print(f"[*] Cache Directory:    {CACHE_DIR}")
    print("="*60)

    # 1. Evidence Auto-Discovery
    mem_files = glob.glob(f"{EVIDENCE_DIR}/**/*.raw", recursive=True) + glob.glob(f"{EVIDENCE_DIR}/**/*.mem", recursive=True)
    raw_disk_images = glob.glob(f"{EVIDENCE_DIR}/**/*.e01", recursive=True) + glob.glob(f"{EVIDENCE_DIR}/**/*.dd", recursive=True) + glob.glob(f"{EVIDENCE_DIR}/**/*.img", recursive=True)
    existing_bodyfiles = glob.glob(f"{EVIDENCE_DIR}/**/bodyfile.txt", recursive=True) + glob.glob(f"{CACHE_DIR}/bodyfile.txt", recursive=True)
    
    has_mem = len(mem_files) > 0
    has_raw_disk = len(raw_disk_images) > 0
    has_bodyfile = len(existing_bodyfiles) > 0
    
    active_bodyfile = existing_bodyfiles[0] if has_bodyfile else None

    # State Resolution: If raw disk exists but no bodyfile, forge it dynamically.
    if has_raw_disk and not has_bodyfile:
        active_bodyfile = generate_bodyfile(raw_disk_images[0])
        if active_bodyfile:
            has_bodyfile = True

    if has_mem: context["Evidence_Files"]["Memory"] = mem_files[0]
    if has_raw_disk: context["Evidence_Files"]["Disk_Image"] = raw_disk_images[0]
    if has_bodyfile: context["Evidence_Files"]["Disk_Bodyfile"] = active_bodyfile

    # Tri-State Logic
    if has_mem and has_bodyfile:
        context["MODE"] = "HYBRID"
    elif has_mem:
        context["MODE"] = "MEMORY_ONLY"
    elif has_bodyfile:
        context["MODE"] = "DISK_ONLY"
    else:
        print("[!] FATAL: No valid evidence or generated cache found.")
        return

    print(f"[*] Tri-State Evaluation: {context['MODE']} Mode Engaged.")

    # 2. Disk Extraction Phase
    if has_bodyfile and active_bodyfile:
        prcarve_registry_map(active_bodyfile)
        context["Available_Caches"].append("registry_map")

    # 3. Memory Extraction Phase
    if has_mem:
        mem_image = mem_files[0]
        state["pstree"] = run_plugin(mem_image, "pstree")
        state["cmdline"] = run_plugin(mem_image, "cmdline")
        context["Available_Caches"].extend(["pstree", "cmdline"])

        if mode == "deep":
            print("[!] INITIATING GLOBAL MEMORY STRIKE. CPU/HDD LOAD INCREASING.")
            state["netscan"] = run_plugin(mem_image, "netscan")
            state["malfind"] = run_plugin(mem_image, "malfind")
            context["Available_Caches"].extend(["netscan", "malfind"])
        else:
            state["netscan"] = '{"status": "SKIPPED - TACTICAL MODE"}'
            state["malfind"] = '{"status": "SKIPPED - TACTICAL MODE"}'

        for key, data in state.items():
            with open(os.path.join(CACHE_DIR, f"{key}.json"), "w") as f:
                f.write(data)

    # Write Context
    with open(os.path.join(CACHE_DIR, "context.json"), "w") as f:
        json.dump(context, f, indent=4)

    print(f"\n[SUCCESS] Environment mapped and caches built at {CACHE_DIR}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--deep", action="store_true", help="Run full global suite.")
    args = parser.parse_args()
    build_environment("deep" if args.deep else "tactical")
