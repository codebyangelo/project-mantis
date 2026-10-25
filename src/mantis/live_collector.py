import os
import re
import json
import socket
import struct
import time
from typing import Dict, List, Tuple, Any
from config import CACHE_DIR, EVIDENCE_DIR
from logger import ExecutionLogger

# =============================================================================
# CONSTANTS & CONFIGURATION
# =============================================================================

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING"
}

# =============================================================================
# CUSTOM PURE-PYTHON X86_64 DISASSEMBLER HELPER
# =============================================================================

def decode_instructions_x86_64(data: bytes, start_addr: int) -> str:
    """
    Decodes basic x86_64 instructions from raw bytes to generate disassembly
    matching patterns searched by sieve_deterministic.py.
    """
    lines = []
    i = 0
    while i < len(data):
        curr_addr = start_addr + i
        addr_hex = f"0x{curr_addr:x}"
        
        # Guard against zero bytes padding
        if data[i:] == b'\x00' * len(data[i:]):
            lines.append(f"{addr_hex}: add byte ptr [rax], al")
            i += len(data[i:])
            break

        # 1. movabs rax, <64-bit imm> (48 b8 val_bytes)
        if i + 9 < len(data) and data[i] == 0x48 and data[i+1] == 0xb8:
            val = struct.unpack("<Q", data[i+2:i+10])[0]
            # Check if followed by jmp rax (ff e0)
            if i + 11 < len(data) and data[i+10] == 0xff and data[i+11] == 0xe0:
                lines.append(f"{addr_hex}: movabs rax, 0x{val:x}")
                lines.append(f"0x{curr_addr+10:x}: jmp rax")
                i += 12
            # Check if followed by sub rcx, rax (48 29 c1)
            elif i + 12 < len(data) and data[i+10] == 0x48 and data[i+11] == 0x29 and data[i+12] == 0xc1:
                lines.append(f"{addr_hex}: movabs rax, 0x{val:x}")
                lines.append(f"0x{curr_addr+10:x}: sub rcx, rax")
                i += 13
            else:
                lines.append(f"{addr_hex}: movabs rax, 0x{val:x}")
                i += 10
            continue
            
        # 2. jmp rax (ff e0)
        if i + 1 < len(data) and data[i] == 0xff and data[i+1] == 0xe0:
            lines.append(f"{addr_hex}: jmp rax")
            i += 2
            continue
            
        # 3. jmp rdx (ff e2)
        if i + 1 < len(data) and data[i] == 0xff and data[i+1] == 0xe2:
            # Check if followed by int3 (cc)
            if i + 2 < len(data) and data[i+2] == 0xcc:
                lines.append(f"{addr_hex}: jmp rdx")
                lines.append(f"0x{curr_addr+2:x}: int3")
                i += 3
            else:
                lines.append(f"{addr_hex}: jmp rdx")
                i += 2
            continue

        # 4. jmp rel32 (e9 offset)
        if i + 4 < len(data) and data[i] == 0xe9:
            offset = struct.unpack("<i", data[i+1:i+5])[0]
            target = curr_addr + 5 + offset
            lines.append(f"{addr_hex}: jmp 0x{target:x}")
            i += 5
            continue

        # 5. jmp rel8 (eb offset)
        if i + 1 < len(data) and data[i] == 0xeb:
            offset = struct.unpack("<b", data[i+1:i+2])[0]
            target = curr_addr + 2 + offset
            lines.append(f"{addr_hex}: jmp 0x{target:x}")
            i += 2
            continue

        # 6. int3 (cc)
        if data[i] == 0xcc:
            lines.append(f"{addr_hex}: int3")
            i += 1
            continue

        # 7. add byte ptr [rax], al (00 00)
        if i + 1 < len(data) and data[i] == 0x00 and data[i+1] == 0x00:
            lines.append(f"{addr_hex}: add byte ptr [rax], al")
            i += 2
            continue
            
        # Fallback raw byte output
        lines.append(f"{addr_hex}: db 0x{data[i]:02x}")
        i += 1

    return " ; ".join(lines)

def generate_hexdump(data: bytes, start_addr: int) -> str:
    """Generates simple formatted hexdump text."""
    lines = []
    for chunk_offset in range(0, len(data), 16):
        chunk = data[chunk_offset:chunk_offset+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{start_addr + chunk_offset:08x}  {hex_str:<47}  |{ascii_str}|")
    return "\n".join(lines)

# =============================================================================
# INGESTION IMPLEMENTATIONS
# =============================================================================

def parse_ip_port(hex_str: str) -> Tuple[str, int]:
    """Parses /proc/net address:port hex string to IP string and port int."""
    ip_hex, port_hex = hex_str.split(":")
    port = int(port_hex, 16)
    
    # Check if IPv6 or IPv4
    if len(ip_hex) == 8:
        # IPv4
        ip_bytes = struct.pack("<I", int(ip_hex, 16))
        ip = socket.inet_ntop(socket.AF_INET, ip_bytes)
    else:
        # IPv6 (packed into 4 32-bit integers)
        ip_bytes = struct.pack("<IIII", 
            int(ip_hex[0:8], 16),
            int(ip_hex[8:16], 16),
            int(ip_hex[16:24], 16),
            int(ip_hex[24:32], 16)
        )
        ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
    return ip, port

def collect_network_connections() -> Dict[str, List[dict]]:
    """
    Parses /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6
    and returns a mapping of socket inode -> connection details dict list.
    """
    connections = {}
    files = [
        ("/proc/net/tcp", "TCPv4"),
        ("/proc/net/tcp6", "TCPv6"),
        ("/proc/net/udp", "UDPv4"),
        ("/proc/net/udp6", "UDPv6")
    ]
    
    for file_path, proto in files:
        if not os.path.exists(file_path):
            continue
        try:
            with open(file_path, "r") as f:
                lines = f.readlines()
                for line in lines[1:]:  # skip header
                    parts = line.strip().split()
                    if len(parts) < 10:
                        continue
                    local_ip, local_port = parse_ip_port(parts[1])
                    rem_ip, rem_port = parse_ip_port(parts[2])
                    state_hex = parts[3]
                    state = TCP_STATES.get(state_hex, "UNKNOWN")
                    inode = parts[9]
                    
                    conn_detail = {
                        "LocalAddr": local_ip,
                        "LocalPort": local_port,
                        "ForeignAddr": rem_ip,
                        "ForeignPort": rem_port,
                        "State": state,
                        "Proto": proto,
                        "inode": inode
                    }
                    if inode not in connections:
                        connections[inode] = []
                    connections[inode].append(conn_detail)
        except Exception as e:
            ExecutionLogger.log("EXTRACTOR", f"Error parsing network file {file_path}: {e}", "WARN")
            
    return connections

def collect_live_telemetry():
    """
    Main collection loop. Triggers proc walks and outputs the json tables.
    """
    ExecutionLogger.log("EXTRACTOR", "Initializing Live Telemetry Collector...")
    start_time = time.time()
    
    os.makedirs(CACHE_DIR, exist_ok=True)
    
    # 1. Map socket inodes to PIDs
    connections_by_inode = collect_network_connections()
    pid_connections = {}  # pid -> connection list
    
    # Flat lists for standard JSON outputs
    flat_pstree = []
    flat_cmdline = []
    flat_netscan = []
    flat_malfind = []
    
    # Temporary holder to structure process tree relationships
    processes = {}  # pid -> proc info dict
    parent_to_children = {}  # ppid -> pid list
    
    # Walk all PIDs in /proc
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        proc_dir = f"/proc/{name}"
        
        try:
            # A. Process status info
            status_path = f"{proc_dir}/status"
            if not os.path.exists(status_path):
                continue
                
            proc_name = ""
            ppid = 0
            with open(status_path, "r") as f:
                for line in f:
                    if line.startswith("Name:"):
                        proc_name = line.split()[1].strip()
                    elif line.startswith("PPid:"):
                        ppid = int(line.split()[1].strip())
            
            # B. Get exe path
            exe_path = ""
            try:
                exe_path = os.readlink(f"{proc_dir}/exe")
            except OSError:
                # Kernel threads or permissions limit
                exe_path = f"[{proc_name}]"
                
            # C. Parse command line args
            args_str = ""
            cmd_path = f"{proc_dir}/cmdline"
            if os.path.exists(cmd_path):
                with open(cmd_path, "rb") as f:
                    cmd_bytes = f.read()
                    # Args are null-byte separated, join them with spaces
                    args_str = cmd_bytes.replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
            
            if not args_str:
                args_str = proc_name
                
            # D. Populate process registry
            proc_info = {
                "PID": pid,
                "PPID": ppid,
                "ImageFileName": proc_name,
                "Path": exe_path,
                "__children": []
            }
            processes[pid] = proc_info
            
            if ppid not in parent_to_children:
                parent_to_children[ppid] = []
            parent_to_children[ppid].append(pid)
            
            # Populate flat command line list
            flat_cmdline.append({
                "PID": pid,
                "Args": args_str
            })
            
            # E. Parse Socket FD mappings
            fd_dir = f"{proc_dir}/fd"
            if os.path.exists(fd_dir):
                try:
                    for fd in os.listdir(fd_dir):
                        fd_path = f"{fd_dir}/{fd}"
                        try:
                            link = os.readlink(fd_path)
                            if link.startswith("socket:["):
                                inode = link[8:-1]
                                if inode in connections_by_inode:
                                    for conn in connections_by_inode[inode]:
                                        conn_entry = conn.copy()
                                        conn_entry["PID"] = pid
                                        # Remove internal inode key from output
                                        conn_entry.pop("inode", None)
                                        flat_netscan.append(conn_entry)
                        except OSError:
                            pass
                except OSError:
                    pass
                    
            # F. Scan memory permissions (Live Malfind)
            maps_path = f"{proc_dir}/maps"
            if os.path.exists(maps_path):
                try:
                    with open(maps_path, "r") as f:
                        for line in f:
                            parts = line.strip().split()
                            if len(parts) < 2:
                                continue
                            addr_range = parts[0]
                            perms = parts[1]
                            
                            # Target anonymous executable memory maps (no file association, or stack/heap check)
                            is_rwx = 'w' in perms and 'x' in perms
                            is_rx = 'r' in perms and 'x' in perms
                            
                            has_no_file = len(parts) < 6 or parts[5].startswith("[") or parts[5].strip() == ""
                            
                            # Standard criteria: unbacked RWX or RX (similar to malfind)
                            if (is_rwx or is_rx) and has_no_file:
                                start_hex, end_hex = addr_range.split("-")
                                start_addr = int(start_hex, 16)
                                end_addr = int(end_hex, 16)
                                size = min(end_addr - start_addr, 1024)  # read max 1KB to avoid memory bloat
                                
                                hex_dump_str = ""
                                disasm_str = ""
                                
                                # Attempt read from process memory space
                                try:
                                    mem_path = f"{proc_dir}/mem"
                                    with open(mem_path, "rb") as mem_f:
                                        mem_f.seek(start_addr)
                                        mem_data = mem_f.read(size)
                                        if mem_data:
                                            hex_dump_str = generate_hexdump(mem_data, start_addr)
                                            disasm_str = decode_instructions_x86_64(mem_data, start_addr)
                                except Exception:
                                    # Fallback when mem cannot be read due to kernel/PTRACE boundaries
                                    hex_dump_str = "[!] Permission Denied to read PID Memory Space"
                                    disasm_str = "[!] Memory Read Blocked"
                                    
                                protection_str = "PAGE_EXECUTE_READWRITE" if is_rwx else "PAGE_EXECUTE_READ"
                                flat_malfind.append({
                                    "PID": pid,
                                    "ProcessName": proc_name,
                                    "Start VPN": f"0x{start_hex}",
                                    "End VPN": f"0x{end_hex}",
                                    "Protection": protection_str,
                                    "Tag": "VadS",
                                    "Disasm": disasm_str,
                                    "Hexdump": hex_dump_str
                                })
                except OSError:
                    pass
                    
        except Exception as e:
            # Gracefully handle processes that closed during iteration
            pass

    # Merge transient processes captured by the background watcher thread
    with TRANSIENT_LOCK:
        for pid, info in list(TRANSIENT_PROCESSES.items()):
            if pid not in processes:
                proc_info = {
                    "PID": pid,
                    "PPID": info["PPID"],
                    "ImageFileName": info["ImageFileName"],
                    "Path": info["Path"],
                    "__children": []
                }
                processes[pid] = proc_info
                
                ppid = info["PPID"]
                if ppid not in parent_to_children:
                    parent_to_children[ppid] = []
                parent_to_children[ppid].append(pid)
                
                flat_cmdline.append({
                    "PID": pid,
                    "Args": info["Args"]
                })
        TRANSIENT_PROCESSES.clear()

    # 2. Build the process tree structure (walk parent links)
    root_nodes = []
    for pid, proc in processes.items():
        ppid = proc["PPID"]
        # If parent process exists in our map, attach as child, else it's a root node
        if ppid in processes and ppid != pid:
            processes[ppid]["__children"].append(proc)
        else:
            root_nodes.append(proc)
            
    # Write to target files
    def safe_write_cache(filename, data):
        path = os.path.join(CACHE_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        ExecutionLogger.log("EXTRACTOR", f"Successfully updated Cache: {filename}")
        
    # === SIMULATED MOCK THREAT INJECTION ===
    if os.environ.get("PM_INJECT_MOCK_THREAT") == "1":
        mock_pid = 99999
        mode = os.environ.get("PM_MOCK_MODE", "TRAMPOLINE").upper()
        
        # 1. Add mock process to pstree (root node)
        root_nodes.append({
            "PID": mock_pid,
            "PPID": 1,
            "ImageFileName": "threat_sim",
            "Path": "/tmp/threat_sim",
            "__children": []
        })
        # 2. Add mock command line args
        flat_cmdline.append({
            "PID": mock_pid,
            "Args": "python3 /tmp/threat_sim --payload reverse_shell"
        })
        # 3. Add mock malfind entry (RWX page)
        if mode == "TRAMPOLINE":
            disasm = "0x7ffff7fde000: movabs rax, 0x12345678abcd ; 0x7ffff7fde00a: jmp rax"
        else:
            # An unknown memory allocation pattern that requires LLM audit
            disasm = "0x7ffff7fde000: push rbx ; 0x7ffff7fde001: mov rbx, rcx ; 0x7ffff7fde004: nop"
            
        flat_malfind.append({
            "PID": mock_pid,
            "ProcessName": "threat_sim",
            "Start VPN": "0x7ffff7fde000",
            "End VPN": "0x7ffff7fdf000",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "Tag": "VadS",
            "Disasm": disasm,
            "Hexdump": "00000000  48 b8 cd ab 78 56 34 12 00 00 ff e0                 |H..xV4....|"
        })
        # 4. Add mock netscan connection (Suspicious external target)
        flat_netscan.append({
            "PID": mock_pid,
            "LocalAddr": "192.168.1.15",
            "LocalPort": 49152,
            "ForeignAddr": "185.190.140.20",
            "ForeignPort": 4444,
            "State": "ESTABLISHED",
            "Proto": "TCPv4"
        })
        ExecutionLogger.log("EXTRACTOR", f"[MOCK INJECT] Injected mock threat PID {mock_pid} (Mode: {mode})", "SUCCESS")

    safe_write_cache("pstree.json", root_nodes)
    safe_write_cache("cmdline.json", flat_cmdline)
    safe_write_cache("netscan.json", flat_netscan)
    safe_write_cache("malfind.json", flat_malfind)
    
    # Mock clean registry/event logs to avoid empty file crashes
    safe_write_cache("hivelist.json", [])
    
    # Save the context.json file
    context = {
        "Investigation_ID": "PM-LIVE-MONITOR",
        "OS": "linux",
        "Evidence_Files": {
            "Memory": "LIVE_SYSTEM",
            "Disk_Image": "LIVE_SYSTEM",
            "Memory_Images": ["LIVE_SYSTEM"],
            "Disk_Images": ["LIVE_SYSTEM"]
        },
        "Cache_Status": "BUILT"
    }
    safe_write_cache("context.json", context)
    
    elapsed = time.time() - start_time
    ExecutionLogger.log("EXTRACTOR", f"Live Ingest Phase Complete. Duration: {elapsed:.2f}s", "SUCCESS")

import threading

# A thread-safe global set to accumulate transient processes seen between runs
TRANSIENT_PROCESSES = {}
TRANSIENT_LOCK = threading.Lock()

def _transient_watcher():
    seen_pids = set()
    while True:
        try:
            current_pids = set()
            for name in os.listdir("/proc"):
                if name.isdigit():
                    pid = int(name)
                    current_pids.add(pid)
                    if pid not in seen_pids:
                        try:
                            # Avoid checking self or system threads
                            proc_name = ""
                            ppid = 0
                            with open(f"/proc/{pid}/status", "r") as sf:
                                for line in sf:
                                    if line.startswith("Name:"):
                                        proc_name = line.split()[1].strip()
                                    elif line.startswith("PPid:"):
                                        ppid = int(line.split()[1].strip())
                            
                            if proc_name.startswith("[") or proc_name.startswith("k"):
                                continue
                                
                            with open(f"/proc/{pid}/cmdline", "rb") as f:
                                cmd_bytes = f.read()
                                args_str = cmd_bytes.replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
                            if not args_str:
                                args_str = proc_name
                                
                            exe_path = ""
                            try:
                                exe_path = os.readlink(f"/proc/{pid}/exe")
                            except OSError:
                                exe_path = f"[{proc_name}]"
                                
                            with TRANSIENT_LOCK:
                                TRANSIENT_PROCESSES[pid] = {
                                    "PID": pid,
                                    "PPID": ppid,
                                    "ImageFileName": proc_name,
                                    "Path": exe_path,
                                    "Args": args_str,
                                    "Timestamp": time.time()
                                }
                        except Exception:
                            pass
            seen_pids = current_pids
        except Exception:
            pass
        time.sleep(0.1) # 100ms polling

# Start the background watcher thread
watcher_thread = threading.Thread(target=_transient_watcher, daemon=True)
watcher_thread.start()

if __name__ == "__main__":
    collect_live_telemetry()
