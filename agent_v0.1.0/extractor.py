import subprocess
import json
import os
import argparse
import time

# --- CENTRALIZED PATHING ---
BASE_DIR = os.path.expanduser("~/projects/findevil_agent/agent_v0.1.0")
CACHE_DIR = os.path.join(BASE_DIR, "evidence_cache")

# External Evidence Mounts
MEM_IMAGE = "/mnt/sift_ext4/evidence/Rocba-Memory/Rocba-Memory.raw"

def run_plugin(plugin, args=[]):
    print(f"[*] Executing windows.{plugin}...")
    # [CORRECTION]: Injected '-r' and 'json' to force Volatility's native JSON renderer
    cmd = ["vol", "-f", MEM_IMAGE, "-r", "json", f"windows.{plugin}"] + args
    start = time.time()
    try:
        # capture_output=True keeps stdout as a string
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[+] {plugin} complete in {time.time() - start:.2f}s.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[!] Error in {plugin}: {e}")
        return f'{{"EXECUTION_ERROR": "{e}"}}' # Return valid fallback JSON

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
        state["netscan"] = '{"status": "SKIPPED - TACTICAL MODE"}'
        state["malfind"] = '{"status": "SKIPPED - TACTICAL MODE"}'

    for key, data in state.items():
        with open(os.path.join(CACHE_DIR, f"{key}.json"), "w") as f:
            # [CORRECTION]: Write the raw string directly to disk. Volatility already 
            # formatted it as valid JSON. Bypassing json.dump saves CPU cycles.
            f.write(data)
            
    print(f"\n[SUCCESS] Global evidence cache built at {CACHE_DIR}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--deep", action="store_true", help="Run full global Volatility suite.")
    args = parser.parse_args()
    build_cache("deep" if args.deep else "tactical")
