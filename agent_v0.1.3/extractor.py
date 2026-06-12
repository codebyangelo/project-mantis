import subprocess
import json
import os
import argparse
import time
import glob

# --- CENTRALIZED PATHING ---
BASE_DIR = os.path.expanduser("~/projects/findevil_agent/agent_v0.1.3")
CACHE_DIR = "/media/analyst/external_drive/project_data/evidence_cache"
EVIDENCE_DIR = "/media/analyst/external_drive/project_data"



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

def detect_partition_offset(disk_image_path):
    """Uses native mmls to determine if the image is a physical disk and extracts the NTFS/Data offset."""
    print(f"[*] Analyzing disk geometry via mmls: {disk_image_path}")
    try:
        result = subprocess.run(["mmls", disk_image_path], capture_output=True, text=True)
        if result.returncode != 0 or "Cannot determine" in result.stderr:
            print("[*] Geometry: Logical Partition detected. No offset required.")
            return None
        
        lines = result.stdout.split('\n')
        for line in lines:
            line_upper = line.upper()
            if "NTFS" in line_upper or "BASIC DATA PARTITION" in line_upper:
                parts = line.split()
                # Standard mmls structure places the Start Sector in the 3rd column (index 2)
                if len(parts) > 3 and parts[2].isdigit():
                    offset = parts[2]
                    print(f"[*] Geometry: Physical Disk detected. Target Offset found at sector {offset}.")
                    return offset
                    
        print("[!] mmls succeeded but no primary Windows partition identified. Defaulting to partition mode.")
        return None
    except FileNotFoundError:
        print("[!] mmls binary missing. Defaulting to partition mode assumption.")
        return None
    except Exception as e:
        print(f"[!] Error reading geometry: {e}. Defaulting to partition mode.")
        return None

def generate_bodyfile(disk_image_path):
    """Dynamically generates bodyfile.txt, autonomously adapting to partition vs. physical disk geometry."""
    print(f"[*] bodyfile.txt absent. Initiating dynamic generation via native 'fls'...")
    output_path = os.path.join(CACHE_DIR, "bodyfile.txt")
    
    offset = detect_partition_offset(disk_image_path)
    
    if offset:
        cmd = f"fls -o {offset} -r -m '/' '{disk_image_path}' > '{output_path}'"
    else:
        cmd = f"fls -r -m '/' '{disk_image_path}' > '{output_path}'"
        
    start = time.time()
    try:
        subprocess.run(cmd, shell=True, check=True)
        print(f"[+] FLS extraction complete. bodyfile.txt forged in {time.time() - start:.2f}s.")
        return output_path
    except subprocess.CalledProcessError as e:
        print(f"[!] FATAL: FLS execution failed: {e}")
        return None

def precarve_registry_map(bodyfile_path):
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
            cmd = f"grep -i '{pattern}' {bodyfile_path} | grep -ivE 'default|public|Windows.old'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')
            
            inodes = []
            for line in lines:
                if line:
                    parts = line.split('|')
                    if len(parts) > 2:
                        inodes.append({"path": parts[1], "inode": parts[2]})
            registry_map[key] = inodes
        except Exception as e:
            print(f"[!] Failed to pre-carve {key}: {e}")
            
    with open(os.path.join(CACHE_DIR, "registry_map.json"), "w") as f:
        json.dump(registry_map, f, indent=4)
    return registry_map

def build_environment(mode):
    os.makedirs(CACHE_DIR, exist_ok=True)
    state = {}
    context = {"MODE": "UNKNOWN", "Available_Caches": [], "Evidence_Files": {}}

    print("\n" + "="*60)
    print(f"[SYSTEM] Initiating UFE Discovery & Extraction (Mode: {mode.upper()})")
    print("="*60)

    # 1. Evidence Auto-Discovery & Idempotency Check
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
        precarve_registry_map(active_bodyfile)
        context["Available_Caches"].append("registry_map")

    # 3. Memory Extraction Phase
    if has_mem:
        mem_image = mem_files[0]
        state["pstree"] = run_plugin(mem_image, "pstree")
        state["cmdline"] = run_plugin(mem_image, "cmdline")
        context["Available_Caches"].extend(["pstree", "cmdline"])

        if mode == "deep":
            print("[!] INITIATING HEAVY IO PLUGINS. CPU/HDD LOAD INCREASING.")
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
