import json
import os
import subprocess
import hashlib

CACHE_DIR = "/mnt/sift_ext4/evidence_cache"
DISK_IMAGE = "/media/analyst/external_drive/project_data/rocba-cdrive.e01"

def read_evidence_cache(plugin_name: str) -> str:
    """Reads the static Volatility output from the JSON cache in milliseconds."""
    filepath = os.path.join(CACHE_DIR, f"{plugin_name}.json")
    try:
        with open(filepath, "r") as f:
            return json.load(f)["data"]
    except FileNotFoundError:
        return f"[!] Cache for {plugin_name} not found. Run extractor.py first."

def extract_and_hash_inode(inode: str) -> str:
    """Uses Sleuth Kit (icat) to carve a payload directly from the E01 disk and hash it."""
    out_file = f"/mnt/sift_ext4/evidence_cache/extracted_{inode}.bin"
    try:
        # 1. Carve the file
        subprocess.run(["icat", "-i", "ewf", "-o", "0", DISK_IMAGE, str(inode)], 
                       stdout=open(out_file, "w"), check=True)
        # 2. Hash the file locally
        sha256 = hashlib.sha256()
        with open(out_file, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
        
        return f"[SUCCESS] Payload extracted to {out_file}. SHA-256: {sha256.hexdigest()}"
    except Exception as e:
        return f"[!] Extraction failed: {e}"
