# FindEvil Agent Source Code

## `agent.py`

```python
import os
from typing import List
from pydantic import BaseModel, Field
from google import genai
from google.genai import types
from logger import ExecutionLogger

class AgentCommand(BaseModel):
    verdict: str = Field(description="Must be 'benign' or 'malicious'. Null hypothesis defaults to 'benign'.")
    confidence_score: float = Field(description="Float from 0.0 to 1.0 indicating certainty in the verdict based on evidence weight.")
    severity_level: str = Field(description="Categorical severity: 'None', 'Low', 'Medium', 'High', 'Critical'. Use 'None' for benign verdicts.")
    reasoning: str = Field(description="Detailed explanation of the verdict, justifying the confidence score and severity.")
    request_memory_carve: bool = Field(description="True if surgical memory string extraction is required to prove a hypothesis.")
    mitre_techniques: List[str] = Field(description="List of applicable MITRE ATT&CK technique IDs (e.g. ['T1055', 'T1036']). Empty if benign.")
class FindEvilAgent:
    def __init__(self):
        ExecutionLogger.log("AGENT", "Initializing Gemini FindEvilAgent with Exhaustive Search & Scoring.")
        if not os.environ.get("GEMINI_API_KEY"):
            ExecutionLogger.log("AGENT", "GEMINI_API_KEY environment variable not set.", "ERROR")
            raise ValueError("[!] GEMINI_API_KEY environment variable not set.")
            
        self.client = genai.Client()
        self.system_instruction = """
        You are the Universal Forensic Engine (v0.2.3). 
        You act as an evaluator for DFIR triage.
        You will receive context about a single suspect PID, including its command line, pstree, heuristic signals, and network bindings.
        
        Your ONLY task is to classify this PID based on the provided evidence.
        
        SCORING RULES:
        - If the PID has benign origins and no severe heuristic signals (like SIG_RWX_INJECTION or SIG_MASQUERADING), output 'benign'.
        - If anomalous DLLs are injected (SIG_RWX_INJECTION) OR highly suspicious outbound network connections exist with process masquerading, output 'malicious'.
          - Set `severity_level` to 'Critical' for known C2/Dropper patterns.
        - Set `request_memory_carve` to True ONLY if you need concrete string evidence (like URLs or domains) from the process memory to prove your verdict. The Surgical Carver will extract strings directly from injected memory regions.
        
        MITRE ATT&CK TAGGING:
        - Assign T1055 (Process Injection) if SIG_RWX_INJECTION is present.
        - Assign T1036 (Masquerading) if SIG_MASQUERADING or filename truncations (e.g. .ex) are present.
        - Assign T1071 (Application Layer Protocol) if suspicious outbound network connections (C2 beacons) are identified.
        
        FOLLOW-UP RULES:
        - When evaluating FOLLOW-UP MEMORY INDICATORS, you MUST consider them alongside the original PSTREE and HEURISTIC evidence.
        - If the new strings contain C2 infrastructure OR the initial evidence (like masquerading names, SIG_RWX_INJECTION) remains highly suspicious, output 'malicious'.
        """
        ExecutionLogger.log("AGENT", "System instructions loaded successfully.")

    def create_session(self):
        ExecutionLogger.log("AGENT", "Creating generative API session with Pydantic JSON schema constraints.")
        config = types.GenerateContentConfig(
            system_instruction=self.system_instruction,
            temperature=0.0,
            response_mime_type="application/json",
            response_schema=AgentCommand
        )
        return self.client.chats.create(model='gemini-3.1-flash-lite', config=config)

```

## `config.py`

```python
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Base directory for the evidence (images, etc.)
EVIDENCE_DIR = os.environ.get("PFE_EVIDENCE_DIR", "/media/analyst/external_drive/project_data")

# Directory where generated caches are stored
CACHE_DIR = os.environ.get("PFE_CACHE_DIR", os.path.join(EVIDENCE_DIR, "evidence_cache"))

# Path to the DFIR playbook
PLAYBOOK_PATH = os.environ.get("PFE_PLAYBOOK_PATH", "/mnt/sift_ext4/dfir_playbook.json")

# Path to the IOC store
IOC_STORE_PATH = os.path.join(BASE_DIR, "ioc_store.json")

# Path to the agent's thought ledger
THOUGHTS_PATH = os.path.join(BASE_DIR, "thoughts.txt")
EXECUTION_LOG_PATH = os.path.join(BASE_DIR, "execution.log")

if not os.path.exists(EVIDENCE_DIR):
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

if not os.path.exists(CACHE_DIR):
    os.makedirs(CACHE_DIR, exist_ok=True)

```

## `extractor.py`

```python
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

```

## `logger.py`

```python
import sys
import datetime
from config import EXECUTION_LOG_PATH

class ExecutionLogger:
    @staticmethod
    def log(component: str, message: str, level: str = "INFO"):
        timestamp = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{timestamp}] [{level}] [{component}] {message}"
        
        # Print to terminal with basic ANSI colors for transparency
        if level == "ERROR" or level == "CRITICAL":
            print(f"\033[91m{formatted}\033[0m")
        elif level == "WARN":
            print(f"\033[93m{formatted}\033[0m")
        elif level == "SUCCESS":
            print(f"\033[92m{formatted}\033[0m")
        else:
            print(formatted)
            
        # Append to execution log
        try:
            with open(EXECUTION_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(formatted + "\n")
        except Exception as e:
            # Fallback if logging fails
            print(f"[!] Logger IO Error: {e}")

```

## `mcp_server.py`

```python
import subprocess
import os
import json
import time
import sys
import threading
import hashlib
import re
from typing import List, Tuple, Set
from config import EVIDENCE_DIR, CACHE_DIR, PLAYBOOK_PATH
from logger import ExecutionLogger

def validate_path(path_str: str) -> str:
    """Validates and resolves a path against allowed sandbox directories to prevent traversal."""
    ExecutionLogger.log("MCP_SERVER", f"Validating path security for: {path_str}")
    if not isinstance(path_str, str) or "\x00" in path_str:
        ExecutionLogger.log("MCP_SERVER", "Validation failed: Null bytes or invalid format.", "ERROR")
        raise ValueError("Invalid path format.")
    
    real_p = os.path.realpath(path_str)
    allowed = [os.path.realpath(EVIDENCE_DIR), os.path.realpath(CACHE_DIR)]
    
    is_allowed = False
    for a in allowed:
        try:
            if os.path.commonpath([a, real_p]) == a:
                is_allowed = True
                break
        except ValueError:
            pass
            
    if not is_allowed:
        ExecutionLogger.log("MCP_SERVER", f"Path traversal blocked: {path_str}", "ERROR")
        raise ValueError(f"Path traversal attempt blocked: {path_str}")
    
    ExecutionLogger.log("MCP_SERVER", f"Path validated securely: {real_p}", "SUCCESS")
    return real_p

def run_with_timer(cmd: list, task_name: str, timeout_sec: int = 300) -> str:
    """Executes a synchronous blocking subprocess without threading."""
    ExecutionLogger.log("MCP_SERVER", f"Starting synchronous subprocess for: {task_name}")
    ExecutionLogger.log("MCP_SERVER", f"Command vector: {cmd}")
    ExecutionLogger.log("MCP_SERVER", f"[*] Tool running... (Timeout: {timeout_sec}s)")
    
    try:
        start_time = time.time()
        result = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=timeout_sec)
        elapsed = time.time() - start_time
        
        if result.returncode != 0:
            ExecutionLogger.log("MCP_SERVER", f"Subprocess failed (exit {result.returncode}): {result.stderr.strip()}", "ERROR")
            return result.stdout if result.stdout else ""
            
        ExecutionLogger.log("MCP_SERVER", f"Task completed in {elapsed:.2f}s: {task_name}", "SUCCESS")
        return result.stdout
    except subprocess.TimeoutExpired:
        ExecutionLogger.log("MCP_SERVER", f"Command timed out after {timeout_sec}s.", "ERROR")
        raise Exception(f"Command timed out after {timeout_sec}s")
    except Exception as e:
        ExecutionLogger.log("MCP_SERVER", f"Subprocess Error: {e}", "ERROR")
        raise Exception(str(e))

def get_evidence_context() -> str:
    ExecutionLogger.log("MCP_SERVER", "Executing get_evidence_context()")
    path = os.path.join(CACHE_DIR, "context.json")
    if os.path.exists(path):
        ExecutionLogger.log("MCP_SERVER", "Context cache found.")
        with open(path, "r") as f:
            return f.read()
    ExecutionLogger.log("MCP_SERVER", "Context cache not found.", "WARN")
    return '{"MODE": "UNKNOWN", "ERROR": "Context not built. Run extractor."}'

def resolve_username_from_pid(pid: str) -> str:
    ExecutionLogger.log("MCP_SERVER", f"Resolving username for PID {pid}...")
    cmdline_path = os.path.join(CACHE_DIR, "cmdline.json")
    if os.path.exists(cmdline_path):
        try:
            with open(cmdline_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
                for entry in data:
                    if str(entry.get("PID")) == str(pid):
                        args = entry.get("Args") or ""
                        match = re.search(r"[uU]sers[\\/]([^\\/]+)", args)
                        if match:
                            user = match.group(1)
                            ExecutionLogger.log("MCP_SERVER", f"Username '{user}' resolved from cmdline.")
                            return user
        except Exception as e:
            ExecutionLogger.log("MCP_SERVER", f"Failed to parse cmdline.json: {e}", "WARN")
            
    pstree_path = os.path.join(CACHE_DIR, "pstree.json")
    if os.path.exists(pstree_path):
        try:
            with open(pstree_path, "r", encoding="utf-8", errors="ignore") as f:
                pstree = json.load(f)
                
            def find_user_in_tree(node):
                if str(node.get("PID")) == str(pid):
                    path = node.get("Path") or ""
                    match = re.search(r"[uU]sers[\\/]([^\\/]+)", path)
                    if match:
                        return match.group(1)
                for child in node.get("__children", []):
                    u = find_user_in_tree(child)
                    if u: return u
                return None

            if isinstance(pstree, list):
                for n in pstree:
                    u = find_user_in_tree(n)
                    if u:
                        ExecutionLogger.log("MCP_SERVER", f"Username '{u}' resolved from pstree.")
                        return u
            else:
                u = find_user_in_tree(pstree)
                if u:
                    ExecutionLogger.log("MCP_SERVER", f"Username '{u}' resolved from pstree.")
                    return u
        except Exception as e:
            ExecutionLogger.log("MCP_SERVER", f"Failed to parse pstree.json: {e}", "WARN")
            
    ExecutionLogger.log("MCP_SERVER", f"Username for PID {pid} could not be resolved.")
    return ""

def query_json_cache(cache_name: str, keyword: str = "") -> str:
    ExecutionLogger.log("MCP_SERVER", f"Executing query_json_cache(cache='{cache_name}', keyword='{keyword}')")
    
    if not re.match(r"^[a-zA-Z0-9_]+$", cache_name):
        ExecutionLogger.log("MCP_SERVER", "Invalid cache name format.", "ERROR")
        return "[!] Invalid cache name."
        
    keyword_str = str(keyword).strip()
    if cache_name == "registry_map" and keyword_str.isdigit():
        ExecutionLogger.log("MCP_SERVER", f"Special handler triggered: Registry Map redirect for PID {keyword_str}")
        user = resolve_username_from_pid(keyword_str)
        reg_map_path = os.path.join(CACHE_DIR, "registry_map.json")
        if os.path.exists(reg_map_path):
            try:
                with open(reg_map_path, "r", encoding="utf-8", errors="ignore") as f:
                    reg_map = json.load(f)
                result_dict = {}
                if "SYSTEM" in reg_map:
                    result_dict["SYSTEM"] = reg_map["SYSTEM"]
                if "SOFTWARE" in reg_map:
                    result_dict["SOFTWARE"] = reg_map["SOFTWARE"]
                if user and "NTUSER" in reg_map:
                    user_ntuser = [e for e in reg_map["NTUSER"] if f"/{user}/" in e.get("path", "").replace("\\", "/").lower()]
                    result_dict["NTUSER"] = user_ntuser if user_ntuser else reg_map["NTUSER"]
                elif "NTUSER" in reg_map:
                    result_dict["NTUSER"] = reg_map["NTUSER"]
                ExecutionLogger.log("MCP_SERVER", f"Registry Map Query successfully redirected and filtered.", "SUCCESS")
                return json.dumps(result_dict, indent=2)
            except Exception as e:
                ExecutionLogger.log("MCP_SERVER", f"Registry redirect failed: {e}", "ERROR")

    try:
        filepath = validate_path(os.path.join(CACHE_DIR, f"{cache_name}.json"))
    except Exception as e:
        return f"[!] {e}"

    if not os.path.exists(filepath):
        ExecutionLogger.log("MCP_SERVER", f"Cache file not found: {filepath}", "WARN")
        return f"[!] Cache for {cache_name} not found."

    try:
        ExecutionLogger.log("MCP_SERVER", f"Reading cache file: {filepath}")
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            raw_content = f.read()

        if cache_name == "malfind" and keyword == "PAGE_EXECUTE_READWRITE":
            try:
                data = json.loads(raw_content)
                pids = list({str(entry.get("PID")) for entry in data if entry.get("Protection") == "PAGE_EXECUTE_READWRITE"})
                if not pids:
                    ExecutionLogger.log("MCP_SERVER", "No PAGE_EXECUTE_READWRITE segments found.")
                    return "[*] No PAGE_EXECUTE_READWRITE segments found."
                ExecutionLogger.log("MCP_SERVER", f"Identified RWX PIDs: {pids}")
                return f"[*] Identified PIDs with PAGE_EXECUTE_READWRITE segments: {', '.join(pids)}"
            except Exception as e:
                ExecutionLogger.log("MCP_SERVER", f"Failed to parse malfind data: {e}", "WARN")

        if not keyword:
            if len(raw_content) > 50000:
                ExecutionLogger.log("MCP_SERVER", "Payload too large without keyword filtering.", "WARN")
                return f"[!] Payload too large. Use a keyword."
            return raw_content

        try:
            data = json.loads(raw_content)
            if isinstance(data, list):
                keyword_str = str(keyword).lower()
                filtered = [e for e in data if isinstance(e, dict) and any(keyword_str in str(k).lower() or keyword_str in str(v).lower() for k, v in e.items())]
                if filtered:
                    ExecutionLogger.log("MCP_SERVER", f"Found {len(filtered)} matching objects in JSON list.", "SUCCESS")
                    out = json.dumps(filtered, indent=2)
                    return out[:8000] + "\n\n[!] OUTPUT TRUNCATED" if len(out) > 8000 else out
                return f"[*] Keyword '{keyword}' not found."
            elif isinstance(data, dict):
                keyword_str = str(keyword).lower()
                filtered = {k: v for k, v in data.items() if keyword_str in str(k).lower() or keyword_str in str(v).lower()}
                if filtered:
                    ExecutionLogger.log("MCP_SERVER", f"Found matching objects in JSON dict.", "SUCCESS")
                    return json.dumps(filtered, indent=2)
        except json.JSONDecodeError:
            ExecutionLogger.log("MCP_SERVER", "File is not JSON, falling back to text search.")
            pass

        matched = [line.strip() for line in raw_content.splitlines() if keyword.lower() in line.lower()]
        if not matched:
            ExecutionLogger.log("MCP_SERVER", f"Keyword '{keyword}' not found in text.")
            return f"[*] Keyword '{keyword}' not found."
        
        ExecutionLogger.log("MCP_SERVER", f"Found {len(matched)} matching lines.", "SUCCESS")
        res = "\n".join(matched)
        return res[:8000] + "\n\n[!] OUTPUT TRUNCATED" if len(res) > 8000 else res

    except Exception as e:
        ExecutionLogger.log("MCP_SERVER", f"Error parsing cache: {e}", "ERROR")
        return f"[!] Error parsing cache: {e}"

def extract_and_carve_hive(inode: str, disk_image_path: str) -> str:
    ExecutionLogger.log("MCP_SERVER", f"Starting Physical Hive Extraction (Inode: {inode})")
    
    if not re.fullmatch(r"[\d\-]+", str(inode)):
        ExecutionLogger.log("MCP_SERVER", "Invalid inode format.", "ERROR")
        return "[!] FATAL: Invalid inode format."
        
    try:
        disk_image_path = validate_path(disk_image_path)
    except Exception as e:
        return f"[!] Path validation failed: {e}"

    if not os.path.exists(disk_image_path):
        ExecutionLogger.log("MCP_SERVER", "Disk image not found.", "ERROR")
        return "[!] Disk image not found."

    try:
        icat_cmd = ["icat", "-i", "ewf", disk_image_path, inode]
        strings_cmd = ["strings", "-el"]
        
        ExecutionLogger.log("MCP_SERVER", f"Executing pipeline: icat {inode} | strings -el")
        icat_proc = subprocess.Popen(icat_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        strings_proc = subprocess.Popen(strings_cmd, stdin=icat_proc.stdout, stdout=subprocess.PIPE, text=True)
        icat_proc.stdout.close()
        
        output, err = strings_proc.communicate(timeout=120)
        
        if strings_proc.returncode != 0:
            ExecutionLogger.log("MCP_SERVER", f"Strings pipeline failed: {err.strip()}", "ERROR")
            return f"[!] Strings pipeline failed: {err.strip()}"
            
        exclusions = ['system32', 'syswow64', 'winsxs', 'program files', 'microsoft.net']
        results = set()
        for line in output.splitlines():
            line_lower = line.lower()
            if 'c:\\' in line_lower and '.dll' in line_lower:
                if not any(excl in line_lower for excl in exclusions):
                    results.add(line.strip())
        
        if not results:
            ExecutionLogger.log("MCP_SERVER", "Hive carve clean.", "SUCCESS")
            return "[*] HIVE CARVE CLEAN: No anomalous absolute DLL paths found."
        
        ExecutionLogger.log("MCP_SERVER", f"Anomaly detected! {len(results)} suspicious DLL paths found.", "WARN")
        return "[!] ANOMALY DETECTED IN HIVE:\n" + "\n".join(sorted(results))
    except subprocess.TimeoutExpired:
        ExecutionLogger.log("MCP_SERVER", "Forensic carve timed out after 120s.", "ERROR")
        icat_proc.kill()
        strings_proc.kill()
        return "[!] ERROR: Forensic carve timed out after 120s."
    except Exception as e:
        ExecutionLogger.log("MCP_SERVER", f"Hive carve error: {e}", "ERROR")
        return f"[!] HIVE CARVE ERROR: {e}"

class SurgicalCarver:
    """
    Targeted memory string extraction using malfind VADs + memmap metadata.
    Zero intermediate disk writes. Context-Bleed-proof.
    """
    STRINGS_RE = re.compile(rb'[ -~]{8,}')

    def __init__(self, memory_image_path: str, cache_dir: str):
        self.memory_image_path = memory_image_path
        self.cache_dir = cache_dir
        self.malfind_cache = self._load_json_cache("malfind")

    def _load_json_cache(self, name: str) -> List[dict]:
        path = os.path.join(self.cache_dir, f"{name}.json")
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []

    def _run_memmap_meta(self, pid: int, timeout: int = 120) -> List[dict]:
        """Runs 'windows.memmap' WITHOUT --dump. Returns only metadata."""
        cmd = [
            "vol", "-f", self.memory_image_path, "-r", "json",
            "windows.memmap", "--pid", str(pid)
        ]
        try:
            ExecutionLogger.log("MCP_SERVER", f"Running fast memmap metadata pass for PID {pid}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if result.returncode != 0 or not result.stdout.strip():
                return []
            return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            return []

    def _get_suspicious_vads(self, pid: int) -> List[Tuple[int, int]]:
        vads = []
        for entry in self.malfind_cache:
            if str(entry.get("PID")) != str(pid):
                continue
            prot = entry.get("Protection", "")
            if "EXECUTE_READWRITE" in prot or "WRITE_COPY" in prot or "READWRITE" in prot:
                start = entry.get("Start") or entry.get("Start VPN") or entry.get("start")
                end = entry.get("End") or entry.get("End VPN") or entry.get("end")
                if start is not None and end is not None:
                    try:
                        vads.append((int(str(start), 0), int(str(end), 0)))
                    except (ValueError, TypeError):
                        continue
        return vads

    @staticmethod
    def _coalesce_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        if not ranges:
            return []
        ranges = sorted(ranges, key=lambda x: x[0])
        merged = [list(ranges[0])]
        for off, size in ranges[1:]:
            last_off, last_size = merged[-1]
            if off <= last_off + last_size:
                new_end = max(last_off + last_size, off + size)
                merged[-1][1] = new_end - last_off
            else:
                merged.append([off, size])
        return [(int(o), int(s)) for o, s in merged]

    def carve_pid(self, pid: int, ioc_regex: re.Pattern, max_matches: int = 100) -> str:
        vads = self._get_suspicious_vads(pid)
        if not vads:
            ExecutionLogger.log("MCP_SERVER", f"No suspicious VADs found for PID {pid}. Trying network fallback.")
            return self.carve_pid_committed_fallback(pid, ioc_regex, max_matches)

        memmap = self._run_memmap_meta(pid)
        targets: List[Tuple[int, int]] = []
        for page in memmap:
            virt = page.get("Virtual")
            if virt is None:
                continue
            try:
                virt_addr = int(str(virt), 0)
            except (ValueError, TypeError):
                continue
            for start, end in vads:
                if start <= virt_addr < end:
                    off = page.get("Offset")
                    size = page.get("Size")
                    if off is not None and size is not None:
                        try:
                            targets.append((int(str(off), 0), int(str(size))))
                        except (ValueError, TypeError):
                            pass
                    break

        if not targets:
            return "[*] NULL HYPOTHESIS: Suspicious VADs are not resident or lack physical backing."

        targets = self._coalesce_ranges(targets)
        matches: Set[str] = set()
        total_scanned = 0

        with open(self.memory_image_path, "rb") as f:
            for off, size in targets:
                f.seek(off)
                remaining = size
                chunk_size = 262144
                while remaining > 0:
                    to_read = min(chunk_size, remaining)
                    chunk = f.read(to_read)
                    if not chunk:
                        break
                    total_scanned += len(chunk)
                    for raw_string in self.STRINGS_RE.findall(chunk):
                        decoded = raw_string.decode("ascii", errors="ignore")
                        if ioc_regex.search(decoded):
                            matches.add(decoded)
                            if len(matches) >= max_matches:
                                break
                    remaining -= len(chunk)
                    if len(matches) >= max_matches:
                        break

        if not matches:
            return "[*] NULL HYPOTHESIS: No IOC strings found in suspicious VAD pages."

        report = "\n".join(sorted(matches))
        return f"[*] SURGICAL CARVE COMPLETE (scanned {total_scanned} bytes):\n{report}"

    def carve_pid_committed_fallback(self, pid: int, ioc_regex: re.Pattern, max_matches: int = 100) -> str:
        memmap = self._run_memmap_meta(pid)
        targets = []
        for page in memmap:
            off = page.get("Offset")
            size = page.get("Size")
            if off is not None and size is not None:
                try:
                    targets.append((int(str(off), 0), int(str(size))))
                except (ValueError, TypeError):
                    continue
        
        targets = self._coalesce_ranges(targets)
        total_budget = 50 * 1024 * 1024
        scanned = 0
        matches = set()
        
        with open(self.memory_image_path, "rb") as f:
            for off, size in targets:
                if scanned >= total_budget:
                    break
                to_read = min(size, total_budget - scanned)
                f.seek(off)
                chunk_size = 262144
                remaining = to_read
                while remaining > 0:
                    read_len = min(chunk_size, remaining)
                    chunk = f.read(read_len)
                    if not chunk:
                        break
                    scanned += len(chunk)
                    for raw_string in self.STRINGS_RE.findall(chunk):
                        decoded = raw_string.decode("ascii", errors="ignore")
                        if ioc_regex.search(decoded):
                            matches.add(decoded)
                            if len(matches) >= max_matches:
                                break
                    remaining -= len(chunk)
                    if len(matches) >= max_matches:
                        break

        if not matches:
            return "[*] NULL HYPOTHESIS: No IOC strings found in committed memory fallback."

        report = "\n".join(sorted(matches))
        return f"[*] SURGICAL FALLBACK CARVE COMPLETE (scanned {scanned} bytes):\n{report}"

def carve_memory_strings(regex_pattern: str, memory_image_path: str, pid: str = "NONE") -> str:
    ExecutionLogger.log("MCP_SERVER", f"Starting surgical string carving for regex '{regex_pattern}' on PID {pid}")
    pid_str = str(pid).strip()
    if not pid_str.isdigit():
        return "[!] FATAL: Surgical carving requires a numeric PID."

    if regex_pattern == "NETWORK" or "http" in regex_pattern.lower():
        ioc_re = re.compile(
            r'(https?://|[a-zA-Z0-9.-]+\.(?:org|cn|biz|net|com|xyz|info)|'
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)',
            re.IGNORECASE
        )
    else:
        try:
            ioc_re = re.compile(regex_pattern, re.IGNORECASE)
        except re.error:
            return "[!] Invalid Regex Pattern"

    carver = SurgicalCarver(memory_image_path, CACHE_DIR)
    return carver.carve_pid(int(pid_str), ioc_re, max_matches=100)

def read_dfir_playbook() -> str:
    ExecutionLogger.log("MCP_SERVER", "Reading DFIR playbook.")
    if os.path.exists(PLAYBOOK_PATH):
        with open(PLAYBOOK_PATH, "r", encoding="utf-8") as f:
            return f.read()
    ExecutionLogger.log("MCP_SERVER", "Playbook not found.", "WARN")
    return "Playbook not found."

```

## `orchestrator.py`

```python
import sys
import os
import json
import time
import datetime
import hashlib
import subprocess
from pydantic import ValidationError

from agent import FindEvilAgent, AgentCommand
from mcp_server import (
    get_evidence_context, query_json_cache,
    extract_and_carve_hive, carve_memory_strings, read_dfir_playbook
)
from config import EVIDENCE_DIR, CACHE_DIR, PLAYBOOK_PATH, IOC_STORE_PATH, THOUGHTS_PATH
from logger import ExecutionLogger

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = THOUGHTS_PATH
IOC_STORE = IOC_STORE_PATH

def write_thought_ledger(phase: str, component: str, details: str):
    timestamp = datetime.datetime.now().astimezone().isoformat()
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] | {phase} | {component}\n{details}\n{'-'*80}\n")

def safe_api_call(chat_session, prompt: str, max_retries: int = 3) -> AgentCommand:
    time.sleep(4)  # Give the API 4 seconds to breathe (RPM limit pacing)
    write_thought_ledger("TX_OUTBOUND", "LLM_EVALUATION", prompt)
    ExecutionLogger.log("ORCHESTRATOR", "Querying Gemini 3.1 Flash-Lite Classifier (Pydantic enforced)...")
    for attempt in range(max_retries):
        try:
            response = chat_session.send_message(prompt)
            write_thought_ledger("RX_INBOUND", "LLM_RAW_OUTPUT", response.text)
            parsed = AgentCommand.model_validate_json(response.text)
            ExecutionLogger.log("ORCHESTRATOR", "Received and successfully validated LLM JSON response.", "SUCCESS")
            return parsed
        except Exception as e:
            delay = 2 * (attempt + 1)
            ExecutionLogger.log("ORCHESTRATOR", f"API Error/Validation Failed: {e}. Retrying in {delay}s...", "WARN")
            time.sleep(delay)
            
    ExecutionLogger.log("ORCHESTRATOR", "API Exhaustion. Falling back to benign state.", "ERROR")
    return AgentCommand(verdict="benign", confidence_score=0.0, severity_level="None", reasoning="API Exhaustion Fallback", request_memory_carve=False, mitre_techniques=[])

def update_ioc_store(new_finding: str):
    ExecutionLogger.log("ORCHESTRATOR", "Committing finding to historical IOC store (atomic write).")
    store = {"tactical_signatures": []}
    if os.path.exists(IOC_STORE):
        try:
            with open(IOC_STORE, "r") as f:
                store = json.load(f)
        except json.JSONDecodeError:
            pass
            
    store["tactical_signatures"].append(new_finding)
    
    tmp_path = IOC_STORE + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(store, f, indent=4)
    os.rename(tmp_path, IOC_STORE)
    ExecutionLogger.log("ORCHESTRATOR", "IOC Store commit successful.", "SUCCESS")

def generate_mitre_report(results: list):
    ExecutionLogger.log("ORCHESTRATOR", "Initiating Exhaustive MITRE ATT&CK Report Generation...")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(BASE_DIR, f"PFE_MITRE_Report_{timestamp}.md")
    
    total_pids = len(results)
    isolated_threats = [r for r in results if r['result'].verdict == "malicious"]
    suspicious_pids = [r for r in results if r['result'].verdict == "suspicious"]
    cleared_pids = [r for r in results if r['result'].verdict == "benign"]
    
    report_content = f"""# Project Find Evil (v0.2.3) - Autonomous DFIR Report
**Date:** {datetime.datetime.now().astimezone().isoformat()}
**Engine Mode:** Exhaustive Python State Machine (Transparent Logging)

## 1. Executive Summary
* **Total PIDs Evaluated:** {total_pids}
* **Threats Isolated:** {len(isolated_threats)}
* **Suspicious (Human Review Required):** {len(suspicious_pids)}
* **Cleared Entities:** {len(cleared_pids)}

---

## 2. Isolated Threats (Malicious)
"""
    if isolated_threats:
        for item in isolated_threats:
            res = item['result']
            report_content += f"### PID {item['pid']}\n"
            report_content += f"- **Severity:** {res.severity_level}\n"
            report_content += f"- **Confidence Score:** {res.confidence_score:.2f}\n"
            report_content += f"- **Reasoning:** {res.reasoning}\n\n"
    else:
        report_content += "*No threats detected.*\n\n"

    report_content += "## 3. Suspicious / Needs Human Review\n"
    if suspicious_pids:
        for item in suspicious_pids:
            res = item['result']
            report_content += f"### PID {item['pid']}\n"
            report_content += f"- **Severity:** {res.severity_level}\n"
            report_content += f"- **Confidence Score:** {res.confidence_score:.2f} (Low Confidence Benign)\n"
            report_content += f"- **Reasoning:** {res.reasoning}\n\n"
    else:
        report_content += "*No suspicious entities requiring review.*\n\n"

    report_content += "## 4. Cleared Entities (Benign)\n"
    if cleared_pids:
        for item in cleared_pids:
            res = item['result']
            report_content += f"- **PID {item['pid']}** | Confidence: {res.confidence_score:.2f} | Reason: {res.reasoning}\n"
    else:
        report_content += "*No entities fully cleared.*\n\n"

    report_content += """
---
## 5. Tactical ATT&CK Mapping
"""
    if isolated_threats:
        unique_techs = set()
        for item in isolated_threats:
            res = item['result']
            if hasattr(res, 'mitre_techniques') and res.mitre_techniques:
                unique_techs.update(res.mitre_techniques)
        
        if not unique_techs:
            report_content += "* No specific MITRE ATT&CK techniques identified by the analyzer.\n"
        else:
            MITRE_NAMES = {
                "T1055": "Process Injection",
                "T1036": "Masquerading",
                "T1071": "Application Layer Protocol"
            }
            for t in sorted(unique_techs):
                name = MITRE_NAMES.get(t, "Unknown Technique")
                report_content += f"* **{name} ({t})**\n"
    else:
        report_content += "* No threats identified, therefore no techniques mapped.\n"

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
        
    hasher = hashlib.sha256()
    with open(report_path, "rb") as f:
        hasher.update(f.read())
    doc_hash = hasher.hexdigest()
    
    ExecutionLogger.log("ORCHESTRATOR", f"Report forged at: {report_path}", "SUCCESS")
    ExecutionLogger.log("ORCHESTRATOR", f"Document Integrity Hash (SHA-256): {doc_hash}")
    
    with open(report_path, "a", encoding="utf-8") as f:
        f.write(f"\n- **Document SHA-256:** {doc_hash}\n")

def get_disk_image() -> str:
    context_path = os.path.join(CACHE_DIR, "context.json")
    if os.path.exists(context_path):
        try:
            with open(context_path, "r") as f:
                return json.load(f).get("Evidence_Files", {}).get("Disk_Image", "")
        except: pass
    return ""

def get_memory_image() -> str:
    context_path = os.path.join(CACHE_DIR, "context.json")
    if os.path.exists(context_path):
        try:
            with open(context_path, "r") as f:
                return json.load(f).get("Evidence_Files", {}).get("Memory", "")
        except: pass
    return ""

def run_fsm_loop(chat_session):
    ExecutionLogger.log("ORCHESTRATOR", "Initializing Exhaustive Deterministic State Machine...")
    
    ctx = get_evidence_context()
    ExecutionLogger.log("ORCHESTRATOR", "Evidence Context Acquired.")
    
    from sieve import get_suspect_pids
    pids_int, pid_table = get_suspect_pids(api_budget=30)
    pids = [str(p) for p in pids_int]
    
    if not pids:
        ExecutionLogger.log("ORCHESTRATOR", "No anomalies crossed the heuristic threshold. Investigation Complete.", "SUCCESS")
        return
        
    ExecutionLogger.log("ORCHESTRATOR", f"Proceeding to iterate {len(pids)} highly-suspect PIDs deterministically.")
    
    investigation_results = []
    
    for pid in sorted(pids, key=int):
        ExecutionLogger.log("ORCHESTRATOR", f"EVALUATING PID: {pid}", "WARN")
        
        data = pid_table.get(int(pid), {})
        signals_str = ", ".join(data.get("signals", [])) if data.get("signals") else "None"
        
        prompt = f"""
        Analyze the following evidence for PID {pid}:
        
        HEURISTIC SIGNALS (Score {data.get('score', 0)}/250):
        {signals_str}
        
        PSTREE:
        {json.dumps(data.get('pstree', {}), indent=2)[:1000]}
        
        CMDLINE:
        {json.dumps(data.get('cmdline', {}), indent=2)[:1000]}
        
        NETSCAN:
        {json.dumps(data.get('netscan', []), indent=2)[:1000]}
        
        MALFIND:
        {json.dumps(data.get('malfind', []), indent=2)[:1000]}
        
        Note: Focus primarily on the Heuristic Signals and the provided context. Does this confirm a threat?
        """
        
        eval_result = safe_api_call(chat_session, prompt)
        ExecutionLogger.log("ORCHESTRATOR", f"LLM Verdict for PID {pid}: {eval_result.verdict.upper()} (Confidence: {eval_result.confidence_score:.2f})")
        ExecutionLogger.log("ORCHESTRATOR", f"LLM Reasoning: {eval_result.reasoning}")
        
        if eval_result.request_memory_carve:
            ExecutionLogger.log("ORCHESTRATOR", "LLM requested dynamic memory carve for NETWORK indicators.")
            mem_img = get_memory_image()
            carve_ev = carve_memory_strings("NETWORK", mem_img, pid)
            ExecutionLogger.log("ORCHESTRATOR", "Dynamic memory carve completed.")
            
            if "NULL HYPOTHESIS" in carve_ev:
                ExecutionLogger.log("ORCHESTRATOR", "No memory indicators found. Retaining initial LLM verdict.", "WARN")
            else:
                ExecutionLogger.log("ORCHESTRATOR", "Feeding memory carve results back to LLM for final verdict.")
                followup_prompt = f"""
                FOLLOW-UP MEMORY INDICATORS FOR PID {pid}:
                {carve_ev[:3000]}
                
                Re-evaluate the PID. Consider BOTH these new memory strings AND the previous evidence. Do these new strings confirm or deny your initial suspicion?
                """
                eval_result = safe_api_call(chat_session, followup_prompt)
                ExecutionLogger.log("ORCHESTRATOR", f"Final LLM Verdict for PID {pid}: {eval_result.verdict.upper()} (Confidence: {eval_result.confidence_score:.2f})")
                
        # Reclassify low confidence benign as suspicious
        if eval_result.verdict == "benign" and eval_result.confidence_score < 0.6:
            ExecutionLogger.log("ORCHESTRATOR", f"Low confidence benign result ({eval_result.confidence_score:.2f}). Flagging as SUSPICIOUS.", "WARN")
            eval_result.verdict = "suspicious"
            eval_result.severity_level = "Review Required"
        
        if eval_result.verdict == "malicious":
            ExecutionLogger.log("ORCHESTRATOR", f"THREAT ISOLATED: PID {pid} is MALICIOUS.", "CRITICAL")
            finding = f"PID {pid} | Severity: {eval_result.severity_level} | Reason: {eval_result.reasoning}"
            update_ioc_store(finding)
            
        investigation_results.append({"pid": pid, "result": eval_result})
            
    ExecutionLogger.log("ORCHESTRATOR", "All suspect PIDs analyzed. Processing final exhaustive report.", "SUCCESS")
    generate_mitre_report(investigation_results)

def verify_and_trigger_cache():
    context_path = os.path.join(CACHE_DIR, "context.json")
    if not os.path.exists(context_path):
        ExecutionLogger.log("ORCHESTRATOR", f"Cache context missing at: {context_path}", "ERROR")
        ExecutionLogger.log("ORCHESTRATOR", "Please run extractor.py manually to build cache.", "WARN")
        sys.exit(1)
    ExecutionLogger.log("ORCHESTRATOR", "Cache context verified.", "SUCCESS")

def main():
    print(f"\033[96m[ PROJECT FIND EVIL - V0.2.3 (EXHAUSTIVE MODE) ]\033[0m")
    print("------------------------------------------------------------")
    
    verify_and_trigger_cache()
    
    try:
        with open(LOG_PATH, "w") as f:
            f.write("=== PROJECT FIND EVIL: HARDENED LOG ===\n\n")
    except Exception as e:
        ExecutionLogger.log("ORCHESTRATOR", f"Failed to initialize thoughts.txt: {e}", "ERROR")
        sys.exit(1)
        
    agent_system = FindEvilAgent()
    chat_session = agent_system.create_session()

    print("\n\033[96m[*] Ready. Type 'investigate' to initiate Exhaustive FSM loop.\033[0m")

    while True:
        try:
            user_input = input("\n[Investigator] > ")
            if user_input.lower() in ['exit', 'quit']: break
            if not user_input.strip(): continue

            if user_input.lower() == 'investigate':
                run_fsm_loop(chat_session)
            else:
                ExecutionLogger.log("CLI", "Command not recognized. Type 'investigate' or 'exit'.", "WARN")

        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()

```

## `sieve.py`

```python
import json
import os
import re
from typing import Dict, List, Tuple, Any
from config import CACHE_DIR
from logger import ExecutionLogger

# =============================================================================
# PHASE 0: PRE-COMPILED PATTERNS (optimized for Celeron: compile once, match many)
# =============================================================================

LOTL_BINARIES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "vssadmin.exe", "msbuild.exe",
    "installutil.exe", "regasm.exe"
}

# Keywords that turn a LOTL binary from "present" to "weaponized"
LOTL_SUSPICIOUS_KEYWORDS = [
    "-enc", "-encodedcommand", "bypass", "-nop", "noprofile", "iex",
    "invoke-expression", "downloadstring", "downloadfile", "invoke-webrequest",
    "bitsadmin", "certutil", "-urlcache", "-split", "-f", "decode", "encode",
    "javascript:", "vbscript:", "scrobj.dll", "shellcode", " -e ", " -ep ",
    "cmd /c", "cmd /k", "powershell -", "rundll32", "regsvr32", "mshta",
    " AppData\\", "\\Temp\\", "\\tmp\\", "\\Users\\Public\\", " -windowstyle hidden"
]

ANOMALOUS_PATH_FRAGMENTS = [
    "\\temp\\", "\\tmp\\", "\\downloads\\", "\\users\\public\\",
    "\\perflogs\\", "\\appdata\\local\\temp\\"
]

PROTECTED_SYSTEM_NAMES = {
    "svchost.exe", "csrss.exe", "lsass.exe", "smss.exe", "services.exe",
    "wininit.exe", "winlogon.exe", "msmpeng.exe", "searchapp.exe",
    "lockapp.exe", "runtimebroker.exe", "smartscreen.exe", "taskhostw.exe",
    "dllhost.exe", "crss.exe"
}

SYSTEM_PATHS = ("\\windows\\system32", "\\windows\\syswow64", "\\program files\\")

OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe"}
BROWSER_PARENTS = {"chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe", "opera.exe"}
SHELL_CHILDREN = LOTL_BINARIES

# Pre-compiled regex for maximum speed on N4020
RE_DOUBLE_EXT = re.compile(r'\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|png|zip)\.(exe|dll|bat|cmd|ps1|js|vbs|py)\b', re.IGNORECASE)
RE_TRUNCATED_EXE = re.compile(r'\.ex[^e]?$', re.IGNORECASE)
RE_IP = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')

KNOWN_GOOD_NET = re.compile(
    r'microsoft|windows|bing|akamai|live\.com|office\.com|skype|'
    r'digicert|verisign|google|gstatic|amazonaws|cloudfront|'
    r'github|outlook|slack|zoom|mozilla|apple|icloud|office365|'
    r'127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.', re.IGNORECASE
)

# =============================================================================
# HELPER FUNCTIONS (pure string ops, zero API calls)
# =============================================================================

def _is_private_or_reserved(ip_str: str) -> bool:
    if not ip_str or ip_str in ("*", "0.0.0.0", "::", "127.0.0.1"):
        return True
    m = RE_IP.match(ip_str.strip())
    if not m:
        return False
    a, b, c, d = map(int, m.groups())
    if a == 10: return True
    if a == 192 and b == 168: return True
    if a == 172 and 16 <= b <= 31: return True
    if a >= 224: return True
    return False

def _score_network(netscan_entries: List[dict]) -> int:
    score = 0
    for conn in netscan_entries:
        foreign = conn.get("ForeignAddr", "")
        foreign_port = conn.get("ForeignPort", 0)
        state = conn.get("State", "")
        proto = conn.get("Proto", "")
        
        if _is_private_or_reserved(foreign):
            continue
        if KNOWN_GOOD_NET.search(foreign):
            continue
        
        # Active external session
        if proto in ("TCPv4", "TCPv6") and state in ("ESTABLISHED", "CLOSE_WAIT", "SYN_SENT"):
            score += 25
        elif "UDP" in proto:
            score += 15
        
        # Non-standard port (not 80, 443, 8080, 8443)
        if foreign_port not in (0, 80, 443, 8080, 8443):
            score += 15
        
        # Listening socket exposed to network
        if state in ("LISTENING", "") and foreign in ("0.0.0.0", "::", "*"):
            score += 20
            
    return min(score, 50)

def _is_anomalous_path(path: str, img: str) -> bool:
    if not path or path.lower() == "null":
        return True
    p = path.lower()
    # Known system process outside system directories = immediate masquerade
    if img.lower() in PROTECTED_SYSTEM_NAMES:
        if not any(sp in p for sp in SYSTEM_PATHS):
            return True
    # Suspicious directories
    if any(bad in p for bad in ANOMALOUS_PATH_FRAGMENTS):
        # Exclude known Microsoft false-positives (OneDrive temp installers, etc.)
        if "\\microsoft\\" in p or "\\onedrive\\" in p or "\\windows\\" in p:
            return False
        return True
    if RE_DOUBLE_EXT.search(p):
        return True
    return False

def _is_masquerading(img: str, path: str) -> bool:
    img_lower = img.lower()
    if RE_TRUNCATED_EXE.search(img):
        return True
    if img_lower in PROTECTED_SYSTEM_NAMES:
        if not any(sp in path.lower() for sp in SYSTEM_PATHS):
            return True
    return False

def _has_suspicious_lotl_args(img: str, args: str) -> bool:
    if not args:
        return False
    a = args.lower()
    i = img.lower()
    
    # Pure script hosts are inherently suspicious in autonomous triage
    if i in ("wscript.exe", "cscript.exe", "mshta.exe"):
        return True
    
    if i in ("powershell.exe", "pwsh.exe", "cmd.exe"):
        if any(kw in a for kw in LOTL_SUSPICIOUS_KEYWORDS):
            return True
    
    if i in ("rundll32.exe", "regsvr32.exe"):
        if any(kw in a for kw in ("javascript:", "vbscript:", ".sct", "scrobj", "\\temp\\", "\\appdata\\", "-i", "/i")):
            return True
    
    if i == "certutil.exe":
        if any(kw in a for kw in ("-urlcache", "-split", "-f", "decode", "encode")):
            return True
    return False

def _is_script_execution(img: str, args: str) -> bool:
    if not args:
        return False
    i, a = img.lower(), args.lower()
    if i in ("python.exe", "pythonw.exe", "py.exe") and (".py" in a or "-c" in a):
        return True
    if i in ("wscript.exe", "cscript.exe") and (".js" in a or ".vbs" in a or ".hta" in a):
        return True
    return True if i == "mshta.exe" else False

def _has_anomalous_parent(pid: int, parent_map: Dict[int, int], table: Dict[int, Any]) -> bool:
    ppid = parent_map.get(pid)
    if not ppid or ppid not in table:
        return False
    parent_img = table[ppid]["pstree"].get("ImageFileName", "").lower()
    child_img = table[pid]["pstree"].get("ImageFileName", "").lower()
    if parent_img in OFFICE_PARENTS and child_img in SHELL_CHILDREN:
        return True
    if parent_img in BROWSER_PARENTS and child_img in SHELL_CHILDREN:
        return True
    return False

def _is_expected_empty_cmdline(img: str) -> bool:
    return img.lower() in {
        "csrss.exe", "smss.exe", "services.exe", "wininit.exe",
        "winlogon.exe", "lsass.exe", "svchost.exe", "registry", "system"
    }

# =============================================================================
# PHASE 1: INGEST & INDEX
# =============================================================================

def build_pid_table() -> Tuple[Dict[int, Any], Dict[int, int]]:
    """
    Loads all JSON caches and flattens pstree into a PID-indexed table.
    Returns: (pid_table, parent_map)
    """
    pid_table: Dict[int, Any] = {}
    parent_map: Dict[int, int] = {}
    
    # --- PSTREE (tree structure -> flatten) ---
    pstree_path = os.path.join(CACHE_DIR, "pstree.json")
    if os.path.exists(pstree_path):
        with open(pstree_path, "r", encoding="utf-8", errors="ignore") as f:
            try:
                pstree_data = json.load(f)
            except:
                pstree_data = []
        
        def _walk(node, parent_pid=None):
            pid = node.get("PID")
            if pid is not None:
                pid = int(pid)
                pid_table[pid] = {
                    "pstree": node,
                    "cmdline": None,
                    "netscan": [],
                    "malfind": [],
                    "score": 0,
                    "signals": []
                }
                # Prefer explicit PPID in node, else tree-derived parent
                explicit_ppid = node.get("PPID")
                if explicit_ppid is not None:
                    parent_map[pid] = int(explicit_ppid)
                elif parent_pid is not None:
                    parent_map[pid] = int(parent_pid)
            current = pid if pid is not None else parent_pid
            for child in node.get("__children", []):
                _walk(child, current)
        
        if isinstance(pstree_data, list):
            for root in pstree_data:
                _walk(root)
        else:
            _walk(pstree_data)
    
    # --- CMDLINE ---
    cmdline_path = os.path.join(CACHE_DIR, "cmdline.json")
    if os.path.exists(cmdline_path):
        with open(cmdline_path, "r", encoding="utf-8", errors="ignore") as f:
            try:
                for entry in json.load(f):
                    pid = entry.get("PID")
                    if pid is not None and int(pid) in pid_table:
                        pid_table[int(pid)]["cmdline"] = entry
            except:
                pass
    
    # --- NETSCAN ---
    netscan_path = os.path.join(CACHE_DIR, "netscan.json")
    if os.path.exists(netscan_path):
        with open(netscan_path, "r", encoding="utf-8", errors="ignore") as f:
            try:
                for entry in json.load(f):
                    pid = entry.get("PID")
                    if pid is not None and int(pid) in pid_table:
                        pid_table[int(pid)]["netscan"].append(entry)
            except:
                pass
    
    # --- MALFIND ---
    malfind_path = os.path.join(CACHE_DIR, "malfind.json")
    if os.path.exists(malfind_path):
        with open(malfind_path, "r", encoding="utf-8", errors="ignore") as f:
            try:
                for entry in json.load(f):
                    pid = entry.get("PID")
                    if pid is not None and int(pid) in pid_table:
                        pid_table[int(pid)]["malfind"].append(entry)
            except:
                pass
    
    return pid_table, parent_map

# =============================================================================
# PHASE 2: DETERMINISTIC SCORING
# =============================================================================

def score_pid_table(pid_table: Dict[int, Any], parent_map: Dict[int, int]) -> List[Tuple[int, int, List[str]]]:
    """
    Sequential scoring pass. Returns list of (pid, score, signals).
    """
    results = []
    
    for pid, data in pid_table.items():
        score = 0
        signals = []
        
        pstree = data.get("pstree") or {}
        cmdline = data.get("cmdline") or {}
        img = pstree.get("ImageFileName", "") or ""
        path = pstree.get("Path", "") or ""
        args = cmdline.get("Args", "") or ""
        
        # 1. RWX Injection (existing primary)
        if any(m.get("Protection") == "PAGE_EXECUTE_READWRITE" for m in data["malfind"]):
            score += 100
            signals.append("SIG_RWX_INJECTION")
        
        # 2. LOTL weaponization
        if _has_suspicious_lotl_args(img, args):
            score += 80
            signals.append("SIG_LOTL_SUSPICIOUS_ARGS")
        elif img.lower() in LOTL_BINARIES:
            score += 10
            signals.append("SIG_LOTL_BENIGN_CONTEXT")
        
        # 3. Script execution
        if _is_script_execution(img, args):
            score += 70
            signals.append("SIG_SCRIPT_EXECUTION")
        
        # 4. Masquerading
        if _is_masquerading(img, path):
            score += 60
            signals.append("SIG_MASQUERADING")
        elif _is_anomalous_path(path, img):
            score += 40
            signals.append("SIG_ANOMALOUS_PATH")
        
        # 5. Network anomalies
        net_score = _score_network(data["netscan"])
        if net_score:
            score += net_score
            signals.append("SIG_SUSPICIOUS_NETWORK")
        
        # 6. Parent-child anomaly
        if _has_anomalous_parent(pid, parent_map, pid_table):
            score += 30
            signals.append("SIG_PARENT_ANOMALY")
        
        # 7. Empty command line (hollow process indicator)
        if not args and not _is_expected_empty_cmdline(img):
            score += 20
            signals.append("SIG_EMPTY_CMDLINE")
        
        # Hard cap to prevent runaway composite scores
        score = min(score, 250)
        data["score"] = score
        data["signals"] = signals
        results.append((pid, score, signals))
    
    return results

# =============================================================================
# PHASE 3: BUDGET-AWARE SELECTION
# =============================================================================

def select_suspects(scored_results: List[Tuple[int, int, List[str]]], api_budget: int = 20) -> List[int]:
    """
    Deterministic selection. Always takes critical (>=150), then fills budget
    with highest high-suspect (60-149). Returns ordered list of PIDs.
    """
    # Sort by score descending, then PID ascending for deterministic tie-breaking
    ranked = sorted(scored_results, key=lambda x: (x[1], -x[0]), reverse=True)
    
    critical = [pid for pid, score, _ in ranked if score >= 150]
    high = [pid for pid, score, _ in ranked if 60 <= score < 150]
    
    suspects = critical[:api_budget]
    remaining = api_budget - len(suspects)
    if remaining > 0:
        suspects.extend(high[:remaining])
    
    # Deduplicate while preserving rank order
    seen = set()
    final = []
    for pid in suspects:
        if pid not in seen:
            seen.add(pid)
            final.append(pid)
    return final

# =============================================================================
# ORCHESTRATOR INTEGRATION
# =============================================================================

def get_suspect_pids(api_budget: int = 20) -> Tuple[List[int], Dict[int, Any]]:
    """
    Drop-in replacement for your existing RWX-only PID selection.
    Returns: (ordered_suspect_pids, pid_table_for_reuse)
    """
    ExecutionLogger.log("ORCHESTRATOR", "SMPT Phase 1: Building multi-signal PID index...")
    pid_table, parent_map = build_pid_table()
    
    ExecutionLogger.log("ORCHESTRATOR", "SMPT Phase 2: Running deterministic scoring...")
    scored = score_pid_table(pid_table, parent_map)
    
    critical = sum(1 for _, s, _ in scored if s >= 150)
    high = sum(1 for _, s, _ in scored if 60 <= s < 150)
    low = sum(1 for _, s, _ in scored if s < 60)
    
    ExecutionLogger.log(
        "ORCHESTRATOR",
        f"SMPT complete. Total={len(scored)} | Critical={critical} | High={high} | Cleared={low}",
        "SUCCESS"
    )
    
    suspects = select_suspects(scored, api_budget=api_budget)
    ExecutionLogger.log("ORCHESTRATOR", f"SMPT Phase 3: Selected {len(suspects)} PIDs for LLM: {suspects}")
    
    return suspects, pid_table

```

