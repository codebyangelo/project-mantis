import subprocess
import re
import json

# --- HARDCODED ZERO-TRUST CONFIGURATION ---
MEM_IMAGE = "/mnt/sift_ext4/evidence/Rocba-Memory/Rocba-Memory.raw"
DISK_IMAGE = "/media/analyst/external_drive/project_data/rocba-cdrive.e01"
HIGH_RISK_BINS = ["lsass.exe", "spoolsv.exe", "rundll32.exe", "powershell.exe", "cmd.exe"]
OUTPUT_FILE = "/mnt/sift_ext4/triage_state_v5.json"

def execute_deterministic_pipeline() -> str:
    """
    Executes the hardware-optimized DFIR pipeline.
    Bypasses recursive pool scanning. Uses strict in-memory correlation.
    Returns the parsed forensic state as a structured JSON string.
    """
    print("\n" + "-"*60)
    print("[BLOCK] Hardware-Optimized Pipeline Execution")
    
    profile = {}
    strike_targets = []

    # PHASE 1: INGESTION (Linear List Walking)
    print("[ACTION] Executing global pstree sweep...")
    try:
        pstree_out = subprocess.run(["vol", "-f", MEM_IMAGE, "windows.pstree"], capture_output=True, text=True, check=True).stdout
        tree_pattern = re.compile(r'^\*?\s*(\d+)\s+(\d+)\s+([a-zA-Z0-9\._\-]+)', re.MULTILINE)
        for match in tree_pattern.finditer(pstree_out):
            pid, ppid, name = match.groups()
            profile[pid] = {"name": name, "ppid": ppid, "cmdline": "", "risk_flags": [], "malfind": "Clean / Not Scanned"}
    except Exception as e:
        return f"[!] Pipeline Failure during pstree: {e}"

    print("[ACTION] Executing global cmdline sweep...")
    try:
        cmd_out = subprocess.run(["vol", "-f", MEM_IMAGE, "windows.cmdline"], capture_output=True, text=True, check=True).stdout
        cmd_pattern = re.compile(r'^(\d+)\s+([a-zA-Z0-9\._\-]+)\s+(.+)$', re.MULTILINE)
        for match in cmd_pattern.finditer(cmd_out):
            pid, name, args = match.groups()
            if pid in profile:
                profile[pid]["cmdline"] = args.strip()
    except Exception as e:
        return f"[!] Pipeline Failure during cmdline: {e}"

    # PHASE 2: IN-MEMORY CORRELATION & TARGET ISOLATION
    suspicious_syntax = [
        "\\temp\\", "\\public\\", "appdata\\local\\temp", 
        "-w hidden", "-windowstyle hidden", "-enc ", "-encodedcommand", 
        "bypass", "invoke-webrequest", "downloadstring", "certutil"
    ]

    for pid, data in profile.items():
        name_lower = data['name'].lower()
        args_lower = data['cmdline'].lower()
        
        # Heuristic 1: Known High-Risk Targets
        if name_lower in HIGH_RISK_BINS:
            data['risk_flags'].append("HIGH_RISK_LOLBIN")
            strike_targets.append((pid, data['name']))
            
        # Heuristic 2: Expanded Attacker Syntax & Paths
        if any(sus in args_lower for sus in suspicious_syntax):
            data['risk_flags'].append("SUSPICIOUS_EXECUTION_SYNTAX")
            if (pid, data['name']) not in strike_targets:
                strike_targets.append((pid, data['name']))

    # PHASE 3: PRECISION STRIKES (The JIT Filter)
    print(f"[ACTION] Launching precision strikes on {len(strike_targets)} isolated targets...")
    for pid, name in strike_targets:
        try:
            malfind_out = subprocess.run(["vol", "-f", MEM_IMAGE, "windows.malfind", "--pid", str(pid)], capture_output=True, text=True).stdout
            
            # The Empirical JIT Filter
            if "00 00 00 00 00 00 00 00" in malfind_out:
                profile[pid]["malfind"] = "VAD Region found, but filtered as benign JIT compiler artifact (Null Bytes)."
            elif "PAGE_EXECUTE" in malfind_out:
                profile[pid]["malfind"] = "**CRITICAL**: Executable injection detected with non-null assembly headers."
        except Exception:
            profile[pid]["malfind"] = "Execution Error during targeted strike."

    # STATE PRESERVATION: The "Broad Ingestion" Fix
    # 1. High-fidelity targets that triggered a hardware memory strike
    actionable_targets = {pid: data for pid, data in profile.items() if data["risk_flags"]}
    
    # 2. Global context: Send all processes with command-line arguments to the agent
    global_context = {
        pid: {"name": data["name"], "cmdline": data["cmdline"], "ppid": data["ppid"]} 
        for pid, data in profile.items() if data["cmdline"]
    }
    
    final_payload = {
        "CRITICAL_STRIKE_RESULTS": actionable_targets,
        "GLOBAL_PROCESS_CONTEXT": global_context
    }
    
    with open(OUTPUT_FILE, "w") as f:
        json.dump(final_payload, f, indent=4)
        
    print("[STATUS] [SUCCESS] Pipeline complete. Handing full telemetry to ReAct Engine.")
    print("-" * 60)
    return json.dumps(final_payload, indent=2)
