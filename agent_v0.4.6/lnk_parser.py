import struct
import subprocess
import os
import json
import re

def get_partition_offset(disk_image_path: str) -> str:
    img_type = "ewf" if disk_image_path.lower().endswith(".e01") else "raw"
    proc = subprocess.run(["mmls", "-i", img_type, disk_image_path], capture_output=True, text=True)
    if proc.returncode != 0:
        return ""
    
    max_len = -1
    best_offset = ""
    for line in proc.stdout.splitlines():
        if "NTFS" in line or "exFAT" in line or "FAT" in line:
            parts = line.split()
            try:
                start_sector = parts[2]
                length = int(parts[4])
                if length > max_len:
                    max_len = length
                    best_offset = start_sector
            except:
                pass
    return best_offset

def parse_lnk_shell_items(inode: str, disk_image_path: str) -> dict:
    """
    Extract LNK binary via icat, parse:
    - LinkTargetIDList (shell items)
    - LinkInfo (volume label, local base path)
    - StringData (relative path, working dir, icon location)
    """
    inode_clean = str(inode).split('-')[0]
    img_type = "ewf" if disk_image_path.lower().endswith(".e01") else "raw"
    offset = get_partition_offset(disk_image_path)
    icat_cmd = ["icat", "-i", img_type]
    if offset:
        icat_cmd.extend(["-o", offset])
    icat_cmd.extend([disk_image_path, inode_clean])
    
    result = {
        "lnk_target_path": "",
        "lnk_baseline_tag": "PATH_BASELINE_UNKNOWN",
        "lnk_drive_type": 0,
        "lnk_is_removable": False,
        "lnk_is_network": False,
        "lnk_drive_letter": ""
    }
    
    try:
        proc = subprocess.run(icat_cmd, capture_output=True, timeout=30)
        if proc.returncode != 0:
            err_msg = proc.stderr.decode('utf-8', errors='ignore').strip()
            if not err_msg:
                err_msg = proc.stdout.decode('utf-8', errors='ignore').strip() or f"icat exited with {proc.returncode}"
            result["lnk_baseline_tag"] = f"PATH_BASELINE_PARSE_ERROR:{err_msg}"
            return result
        lnk_data = proc.stdout
        if len(lnk_data) < 76:
            result["lnk_baseline_tag"] = "PATH_BASELINE_PARSE_ERROR:LNK file too small"
            return result
            
        flags = struct.unpack('<I', lnk_data[20:24])[0]
        has_target_id_list = (flags & 0x01) != 0
        has_link_info = (flags & 0x02) != 0
        has_name = (flags & 0x04) != 0
        has_rel_path = (flags & 0x08) != 0
        has_working_dir = (flags & 0x10) != 0
        has_cmd_args = (flags & 0x20) != 0
        has_icon_loc = (flags & 0x40) != 0
        
        offset = 76
        if has_target_id_list:
            id_list_size = struct.unpack('<H', lnk_data[offset:offset+2])[0]
            offset += 2 + id_list_size
            
        target_path = ""
        is_removable = False
        is_network = False
        drive_letter = ""
        
        if has_link_info:
            li_size, li_hdr_size, li_flags, vol_id_ofs, local_path_ofs, net_ofs, suffix_ofs = struct.unpack('<IIIIIII', lnk_data[offset:offset+28])
            
            if li_flags & 0x01: # Local
                vol_offset = offset + vol_id_ofs
                drive_type = struct.unpack('<I', lnk_data[vol_offset+4:vol_offset+8])[0]
                if drive_type == 2: is_removable = True
                if drive_type == 4: is_network = True
                result["lnk_drive_type"] = drive_type
                
                path_ofs = offset + local_path_ofs
                end_ofs = path_ofs
                while end_ofs < len(lnk_data) and lnk_data[end_ofs] != 0: end_ofs+=1
                target_path = lnk_data[path_ofs:end_ofs].decode('ascii', errors='ignore')
                drive_letter = target_path[0:2] if len(target_path) >= 2 and target_path[1] == ':' else ""
                
            elif li_flags & 0x02: # Network
                is_network = True
                path_ofs = offset + net_ofs
                end_ofs = path_ofs + 20
                while end_ofs < len(lnk_data) and lnk_data[end_ofs] != 0: end_ofs+=1
                target_path = lnk_data[path_ofs+20:end_ofs].decode('ascii', errors='ignore')
            
            offset += li_size
            
        def read_string_data(data, ofs):
            if ofs >= len(data): return "", ofs
            length = struct.unpack('<H', data[ofs:ofs+2])[0]
            ofs += 2
            s = data[ofs:ofs+length*2].decode('utf-16le', errors='ignore')
            return s, ofs + length*2

        name_str = rel_path_str = working_dir_str = cmd_args_str = icon_loc_str = ""
        
        if has_name: name_str, offset = read_string_data(lnk_data, offset)
        if has_rel_path: rel_path_str, offset = read_string_data(lnk_data, offset)
        if has_working_dir: working_dir_str, offset = read_string_data(lnk_data, offset)
        if has_cmd_args: cmd_args_str, offset = read_string_data(lnk_data, offset)
        if has_icon_loc: icon_loc_str, offset = read_string_data(lnk_data, offset)
        
        if not target_path and rel_path_str:
            target_path = rel_path_str
            
        result["lnk_target_path"] = target_path
        result["lnk_is_removable"] = is_removable
        result["lnk_is_network"] = is_network
        result["lnk_drive_letter"] = drive_letter
        
        if target_path:
            t_lower = target_path.lower()
            if t_lower.startswith("\\\\"):
                ip_match = re.search(r"\\\\([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", t_lower)
                if ip_match:
                    result["lnk_baseline_tag"] = f"NET_BASELINE_CORPORATE:{ip_match.group(1)}"
                else:
                    host = t_lower.split('\\')[2] if len(t_lower.split('\\')) > 2 else "unknown"
                    result["lnk_baseline_tag"] = f"NET_BASELINE_CORPORATE:{host}"
            elif is_removable:
                result["lnk_baseline_tag"] = f"PATH_BASELINE_REMOVABLE:{drive_letter.upper().replace(':','')}"
            elif "c:\\users\\" in t_lower:
                if "\\desktop" in t_lower:
                    result["lnk_baseline_tag"] = "PATH_BASELINE_LOCAL:desktop"
                elif "\\templates" in t_lower:
                    result["lnk_baseline_tag"] = "PATH_BASELINE_LOCAL:templates"
                else:
                    result["lnk_baseline_tag"] = "PATH_BASELINE_LOCAL:user_profile"
            else:
                result["lnk_baseline_tag"] = "PATH_BASELINE_LOCAL:other"
    except Exception as e:
        result["lnk_baseline_tag"] = f"PATH_BASELINE_PARSE_ERROR:{str(e)}"
        
    return result
