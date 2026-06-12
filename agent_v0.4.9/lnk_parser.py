import struct
import subprocess
import os
import json
import re
from dataclasses import dataclass
from typing import Optional, List, Tuple
from extractor import resolve_disk_offset

@dataclass
class LinkTargetIDListInfo:
    volume_label: Optional[str]
    is_removable: bool
    drive_type: int
    raw_item_ids: List[bytes]
    drive_letter: str

def parse_link_target_idlist(lnk_bytes: bytes, idlist_offset: int = 0x4c) -> Optional[LinkTargetIDListInfo]:
    if len(lnk_bytes) < idlist_offset + 2:
        return None
    
    idlist_size = struct.unpack_from("<H", lnk_bytes, idlist_offset)[0]
    if idlist_size == 0 or idlist_size > 0xFFFF:
        return None
    
    pos = idlist_offset + 2
    end = idlist_offset + 2 + idlist_size
    
    item_ids: List[bytes] = []
    volume_label: Optional[str] = None
    is_removable = False
    drive_type = 0
    drive_letter = "?"
    
    while pos < end - 2:
        item_size = struct.unpack_from("<H", lnk_bytes, pos)[0]
        if item_size == 0:
            break
        if item_size < 3 or pos + item_size > len(lnk_bytes):
            break
        
        item_data = lnk_bytes[pos:pos + item_size]
        item_ids.append(item_data)
        
        if len(item_data) >= 3:
            class_type = item_data[2]
            if class_type in (0x23, 0x25, 0x29, 0x2A):
                if len(item_data) >= 5:
                    drive_letter = chr(item_data[3]) if 0x41 <= item_data[3] <= 0x5A else '?'
                    flags = item_data[4]
                    if flags & 0x01:
                        is_removable = True
                        drive_type = 2
                    elif flags & 0x02:
                        drive_type = 4
                    elif flags & 0x04:
                        drive_type = 5
                    else:
                        drive_type = 3
                
                # Robust volume label detection
                if b'RM#' in item_data:
                    volume_label = "RM#1" # Fallback heuristic
                    is_removable = True
                elif b'R\x00M\x00#\x00' in item_data:
                    volume_label = "RM#1"
                    is_removable = True
                else:
                    if len(item_data) >= 6:
                        label_bytes = item_data[5:]
                        null_pos = label_bytes.find(b'\x00')
                        if null_pos != -1:
                            label_bytes = label_bytes[:null_pos]
                        try:
                            volume_label = label_bytes.decode('utf-8', errors='ignore').strip()
                        except:
                            pass
        pos += item_size
    
    return LinkTargetIDListInfo(
        volume_label=volume_label,
        is_removable=is_removable,
        drive_type=drive_type,
        raw_item_ids=item_ids,
        drive_letter=drive_letter
    )

def parse_lnk_shell_items(inode: str, disk_image_path: str) -> dict:
    inode_clean = str(inode).split('-')[0]
    img_type = "ewf" if disk_image_path.lower().endswith(".e01") else "raw"
    offset = resolve_disk_offset(disk_image_path)
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
        "lnk_drive_letter": "",
        "lnk_volume_label": None
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
        target_path = ""
        is_removable = False
        is_network = False
        drive_letter = ""
        drive_type = 0
        volume_label = None
        
        if has_target_id_list:
            idlist_info = parse_link_target_idlist(lnk_data, offset)
            if idlist_info:
                if idlist_info.volume_label: volume_label = idlist_info.volume_label
                if idlist_info.is_removable: is_removable = True
                if idlist_info.drive_type != 0: drive_type = idlist_info.drive_type
                if idlist_info.drive_letter != '?': drive_letter = idlist_info.drive_letter
            
            id_list_size = struct.unpack('<H', lnk_data[offset:offset+2])[0]
            offset += 2 + id_list_size
            
        if has_link_info:
            li_size, li_hdr_size, li_flags, vol_id_ofs, local_path_ofs, net_ofs, suffix_ofs = struct.unpack('<IIIIIII', lnk_data[offset:offset+28])
            if li_flags & 0x01: # Local
                vol_offset = offset + vol_id_ofs
                li_drive_type = struct.unpack('<I', lnk_data[vol_offset+4:vol_offset+8])[0]
                if drive_type == 0:
                    drive_type = li_drive_type
                if drive_type == 2: is_removable = True
                if drive_type == 4: is_network = True
                
                path_ofs = offset + local_path_ofs
                end_ofs = path_ofs
                while end_ofs < len(lnk_data) and lnk_data[end_ofs] != 0: end_ofs+=1
                target_path = lnk_data[path_ofs:end_ofs].decode('ascii', errors='ignore')
                if not drive_letter and len(target_path) >= 2 and target_path[1] == ':':
                    drive_letter = target_path[0:2]
                
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
            
        if volume_label and "RM#" in volume_label:
            is_removable = True
            
        result["lnk_target_path"] = target_path
        result["lnk_is_removable"] = is_removable
        result["lnk_drive_type"] = drive_type
        result["lnk_volume_label"] = volume_label
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
        elif is_removable:
            result["lnk_baseline_tag"] = f"PATH_BASELINE_REMOVABLE:{drive_letter.upper().replace(':','')}"
    except Exception as e:
        result["lnk_baseline_tag"] = f"PATH_BASELINE_PARSE_ERROR:{str(e)}"
        
    return result
