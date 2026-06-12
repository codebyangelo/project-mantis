import subprocess
import os
import re
import json

def extract_usbstor_from_hive(hive_path: str) -> list:
    """
    Parse SYSTEM hive for USBSTOR keys using rip.pl
    """
    cmd = ["rip.pl", "-r", hive_path, "-p", "usbstor"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            return []
            
        output = proc.stdout
        devices = []
        current_dev = {}
        
        # very simple parser for RegRipper's usbstor plugin
        for line in output.splitlines():
            line = line.strip()
            if not line: continue
            
            # e.g. "Device        : Kingston DataTraveler 3.0"
            if line.startswith("Device") and ":" in line:
                if current_dev: devices.append(current_dev)
                current_dev = {"device_name": line.split(":", 1)[1].strip()}
            elif line.startswith("Serial") and ":" in line:
                current_dev["serial"] = line.split(":", 1)[1].strip()
            elif line.startswith("S/N") and ":" in line:
                current_dev["serial"] = line.split(":", 1)[1].strip()
            elif "VID_" in line and "PID_" in line:
                # Might just be the raw subkey line
                current_dev["vid_pid"] = line
            elif line.startswith("LastWrite") and ":" in line:
                current_dev["last_write_time"] = line.split(":", 1)[1].strip()
            
            # generic fallback if RegRipper format varies
            elif "Disk&Ven_" in line:
                if current_dev: devices.append(current_dev)
                current_dev = {"device_name": line}
                
        if current_dev:
            devices.append(current_dev)
            
        return devices
    except Exception:
        return []
