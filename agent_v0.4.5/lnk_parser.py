import struct
import subprocess
import os
import json

def resolve_lnk_target(inode: str, disk_image_path: str) -> dict:
    inode_clean = inode.split('-')[0]
    img_type = "ewf" if disk_image_path.lower().endswith(".e01") else "raw"
    icat_cmd = ["icat", "-i", img_type, disk_image_path, inode_clean]
    try:
        proc = subprocess.run(icat_cmd, capture_output=True, timeout=30)
        if proc.returncode != 0:
            return None
        lnk_data = proc.stdout
        if len(lnk_data) < 76:
            return None
            
        flags = struct.unpack('<I', lnk_data[20:24])[0]
        has_target_id_list = (flags & 0x01) != 0
        has_link_info = (flags & 0x02) != 0
        
        offset = 76
        if has_target_id_list:
            id_list_size = struct.unpack('<H', lnk_data[offset:offset+2])[0]
            offset += 2 + id_list_size
            
        if has_link_info:
            li_size, li_hdr_size, li_flags, vol_id_ofs, local_path_ofs, net_ofs, suffix_ofs = struct.unpack('<IIIIIII', lnk_data[offset:offset+28])
            
            target_path = ""
            drive_type = 0
            is_removable = False
            is_network = False
            drive_letter = ""
            
            if li_flags & 0x01: # Local
                vol_offset = offset + vol_id_ofs
                drive_type = struct.unpack('<I', lnk_data[vol_offset+4:vol_offset+8])[0]
                if drive_type == 2: is_removable = True
                if drive_type == 4: is_network = True
                
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
                
            return {
                "lnk_target_path": target_path,
                "lnk_drive_type": drive_type,
                "lnk_is_removable": is_removable,
                "lnk_is_network": is_network,
                "lnk_drive_letter": drive_letter
            }
    except Exception:
        pass
    return None
