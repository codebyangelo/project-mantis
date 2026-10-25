#!/usr/bin/env python3
# mock_playbook_test.py
# Programmatic mock test verifying execution of all Linux Playbook Threat Vectors.

import os
import json
import shutil
import subprocess
import glob
import re

# Base config paths
EVIDENCE_DIR = "/sdcard/Download/evidence"
CACHE_DIR = os.path.join(EVIDENCE_DIR, "evidence_cache")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def clean_cache():
    print("[*] Flushing Cache folder...")
    if os.path.exists(CACHE_DIR):
        shutil.rmtree(CACHE_DIR)
    os.makedirs(CACHE_DIR, exist_ok=True)

def write_telemetry():
    print("[*] Injecting Playbook Mock Telemetry...")
    
    # 1. context.json
    context = {
        "Investigation_ID": "PM-MOCK-PLAYBOOK-TEST",
        "OS": "linux",
        "Evidence_Files": {
            "Memory": "LIVE_SYSTEM",
            "Disk_Image": "LIVE_SYSTEM",
            "Memory_Images": ["LIVE_SYSTEM"],
            "Disk_Images": ["LIVE_SYSTEM"]
        },
        "Cache_Status": "BUILT"
    }
    with open(os.path.join(CACHE_DIR, "context.json"), "w") as f:
        json.dump(context, f, indent=4)
        
    # 2. pstree.json (including masquerade cron and injected threat_sim PIDs)
    pstree = [
        {
            "PID": 1,
            "PPID": 0,
            "ImageFileName": "init",
            "Path": "/sbin/init",
            "__children": [
                {
                    "PID": 99999,
                    "PPID": 1,
                    "ImageFileName": "threat_sim",
                    "Path": "/tmp/threat_sim",
                    "__children": []
                },
                {
                    "PID": 88888,
                    "PPID": 1,
                    "ImageFileName": "cron",
                    "Path": "/tmp/cron", # Outside /usr/sbin/ -> masquerading!
                    "__children": []
                }
            ]
        }
    ]
    with open(os.path.join(CACHE_DIR, "pstree.json"), "w") as f:
        json.dump(pstree, f, indent=4)
        
    # 3. cmdline.json
    cmdline = [
        {
            "PID": 99999,
            "Args": "python3 /tmp/threat_sim --payload reverse_shell"
        },
        {
            "PID": 88888,
            "Args": "/tmp/cron -f"
        }
    ]
    with open(os.path.join(CACHE_DIR, "cmdline.json"), "w") as f:
        json.dump(cmdline, f, indent=4)
        
    # 4. malfind.json (containing malicious trampoline mapping for threat_sim)
    malfind = [
        {
            "PID": 99999,
            "ProcessName": "threat_sim",
            "Start VPN": "0x7ffff7fde000",
            "End VPN": "0x7ffff7fdf000",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "Tag": "VadS",
            "Disasm": "0x7ffff7fde000: movabs rax, 0x12345678abcd ; 0x7ffff7fde00a: jmp rax",
            "Hexdump": "00000000  48 b8 cd ab 78 56 34 12 00 00 ff e0                 |H..xV4....|"
        }
    ]
    with open(os.path.join(CACHE_DIR, "malfind.json"), "w") as f:
        json.dump(malfind, f, indent=4)
        
    # 5. netscan.json & hivelist.json
    with open(os.path.join(CACHE_DIR, "netscan.json"), "w") as f:
        json.dump([], f)
    with open(os.path.join(CACHE_DIR, "hivelist.json"), "w") as f:
        json.dump([], f)
        
    # 6. bodyfile_mock.txt (injecting file exfiltration, collection script, payload, and data deletion)
    bodyfile_content = (
        "0|/home/user/downloads/exfiltrated_staging.zip|10001|r/rrw-r--r--|0|0|50000|1718970000|1718970000|1718970000|1718970000\n"
        "0|/tmp/automated_collector.sh|10002|r/rrw-r--r--|0|0|1024|1718970000|1718970000|1718970000|1718970000\n"
        "0|/dev/shm/dropped_payload.elf|10003|r/rrwx------|0|0|20480|1718970000|1718970000|1718970000|1718970000\n"
        "0|/home/user/documents/confidential_wiped.deleted|10004|r/rrw-r--r--|0|0|0|1718970000|1718970000|1718970000|1718970000\n"
    )
    with open(os.path.join(CACHE_DIR, "bodyfile_mock.txt"), "w") as f:
        f.write(bodyfile_content)

def run_orchestrator():
    print("[*] Running Orchestrator against Mock Telemetry...")
    env = os.environ.copy()
    env["PM_LLM_PROVIDER"] = os.environ.get("PM_LLM_PROVIDER", "gemini_free")
    env["OPENAI_API_KEY"] = os.environ.get("OPENAI_API_KEY", "")
    env["OPENAI_MODEL_NAME"] = os.environ.get("OPENAI_MODEL_NAME", "gemini-2.5-flash")
    
    repo_root = os.path.abspath(os.path.join(BASE_DIR, ".."))
    src_dir = os.path.join(repo_root, "src")
    env["PYTHONPATH"] = f"{src_dir}:{env.get('PYTHONPATH', '')}"
    cmd = ["python3", "-m", "mantis.orchestrator"]
    subprocess.run(cmd, cwd=repo_root, env=env)

def verify_report():
    print("\n" + "="*50)
    print(" VERIFICATION SUMMARY: PLAYBOOK THREAT VECTORS")
    print("="*50)
    
    # Locate latest generated report
    reports = glob.glob(os.path.join(BASE_DIR, "PM_MITRE_Report_*.md"))
    if not reports:
        print("[!] Error: No report generated.")
        return
        
    latest_report = max(reports, key=os.path.getctime)
    print(f"Reading latest report: {os.path.basename(latest_report)}\n")
    
    with open(latest_report, "r") as f:
        content = f.read()
        
    targets = {
        "PROC_INJ_001 (Process Injection)": [r"Entity: PID 99999", r"threat_sim"],
        "PROC_MASQ_001 (Masquerading)": [r"Entity: PID 88888", r"cron"],
        "DATA_EXFIL_001 (Staging Archive)": [r"Entity: /home/user/downloads/exfiltrated_staging\.zip"],
        "COLLECTION_001 (Collection Script)": [r"Entity: /tmp/automated_collector\.sh"],
        "EXECUTION_001 (Dropped Payload)": [r"Entity: /dev/shm/dropped_payload\.elf"],
        "ANTI_FORENSICS_001 (Anti-Forensics)": [r"Entity: /home/user/documents/confidential_wiped\.deleted"]
    }
    
    all_found = True
    for rule, keywords in targets.items():
        found = all(re.search(kw, content, re.IGNORECASE) for kw in keywords)
        status = "\033[92m[ DETECTED ]\033[0m" if found else "\033[91m[ NOT FOUND ]\033[0m"
        print(f" * {rule:<40} {status}")
        if not found:
            all_found = False
            
    print("="*50)
    if all_found:
        print("\033[92m[SUCCESS] All Linux Playbook threat vectors successfully executed & detected!\033[0m")
    else:
        print("\033[91m[FAILURE] Some threat vectors were missing from the final report.\033[0m")
    print("="*50)

if __name__ == "__main__":
    clean_cache()
    write_telemetry()
    run_orchestrator()
    verify_report()
