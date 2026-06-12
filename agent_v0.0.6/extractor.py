#!/usr/bin/env python3
import subprocess
import json
import os
import argparse
import time

CACHE_DIR = "/mnt/sift_ext4/evidence_cache"
MEM_IMAGE = "/mnt/sift_ext4/evidence/Rocba-Memory/Rocba-Memory.raw"

def run_plugin(plugin, args=[]):
    print(f"[*] Executing windows.{plugin} (This may take significant time)...")
    cmd = ["vol", "-f", MEM_IMAGE, f"windows.{plugin}"] + args
    start = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"[+] {plugin} complete in {time.time() - start:.2f}s.")
    return result.stdout

def build_cache(mode):
    os.makedirs(CACHE_DIR, exist_ok=True)
    state = {}

    # Core Structural Ingestion (Always Run)
    state["pstree"] = run_plugin("pstree")
    state["cmdline"] = run_plugin("cmdline")

    if mode == "deep":
        print("[!] INITIATING 2-HOUR GLOBAL STRIKE. DO NOT INTERRUPT.")
        state["netscan"] = run_plugin("netscan")
        state["malfind"] = run_plugin("malfind")
    else:
        print("[*] Tactical mode. Skipping global netscan/malfind.")
        state["netscan"] = "SKIPPED - TACTICAL MODE"
        state["malfind"] = "SKIPPED - TACTICAL MODE"

    # Write the static JSON cache
    for key, data in state.items():
        with open(os.path.join(CACHE_DIR, f"{key}.json"), "w") as f:
            json.dump({"data": data}, f)
            
    print(f"\n[SUCCESS] Evidence cache built at {CACHE_DIR}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--deep", action="store_true", help="Run 2-hour global Volatility suite.")
    args = parser.parse_args()
    build_cache("deep" if args.deep else "tactical")
