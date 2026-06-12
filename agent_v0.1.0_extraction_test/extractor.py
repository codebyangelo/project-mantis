#!/usr/bin/env python3
import subprocess
import json
import os
import argparse
import time

# --- CENTRALIZED PATHING ---
BASE_DIR = os.path.expanduser("~/projects/findevil_agent/agent_v0.1.0_extraction_test")
CACHE_DIR = os.path.join(BASE_DIR, "evidence_cache")

# External Evidence Mounts
MEM_IMAGE = "/mnt/sift_ext4/evidence/Rocba-Memory/Rocba-Memory.raw"

def run_plugin(plugin, args=[]):
    print(f"[*] Executing windows.{plugin}...")
    cmd = ["vol", "-f", MEM_IMAGE, f"windows.{plugin}"] + args
    start = time.time()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[+] {plugin} complete in {time.time() - start:.2f}s.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[!] Error in {plugin}: {e}")
        return f"EXECUTION ERROR: {e}"

def build_cache(mode):
    os.makedirs(CACHE_DIR, exist_ok=True)
    state = {}

    print("\n" + "="*60)
    print(f"[SYSTEM] Initiating {mode.upper()} Cache Build on {MEM_IMAGE}")
    print("="*60)

    state["pstree"] = run_plugin("pstree")
    state["cmdline"] = run_plugin("cmdline")

    if mode == "deep":
        print("[!] INITIATING HEAVY IO PLUGINS. CPU/HDD LOAD INCREASING.")
        state["netscan"] = run_plugin("netscan")
        state["malfind"] = run_plugin("malfind")
    else:
        state["netscan"] = "SKIPPED - TACTICAL MODE"
        state["malfind"] = "SKIPPED - TACTICAL MODE"

    for key, data in state.items():
        with open(os.path.join(CACHE_DIR, f"{key}.json"), "w") as f:
            json.dump({"data": data}, f)
            
    print(f"\n[SUCCESS] Global evidence cache built at {CACHE_DIR}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--deep", action="store_true", help="Run full global Volatility suite.")
    args = parser.parse_args()
    build_cache("deep" if args.deep else "tactical")
