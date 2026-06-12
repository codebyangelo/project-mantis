import sys
import struct
import subprocess
import glob

def dump():
    img_path = "/media/analyst/external_drive/project_data/cfreds/cfreds_2015_data_leakage_pc.dd"
    proc = subprocess.run(["fls", "-r", img_path], capture_output=True, text=True)
    inode = None
    for line in proc.stdout.splitlines():
        if "design_concept.lnk" in line.lower():
            # example line: r/r 1234-128-4: path/to/file.lnk
            inode = line.split()[1].split('-')[0].strip(':')
            break
    if not inode:
        print("Inode not found!")
        return
        
    print(f"Inode: {inode}")
    icat_cmd = ["icat", "-i", "ewf", img_path, inode]
    proc = subprocess.run(icat_cmd, capture_output=True)
    lnk_data = proc.stdout
    print(f"LNK Size: {len(lnk_data)}")
    
    offset = 76
    id_list_size = struct.unpack('<H', lnk_data[offset:offset+2])[0]
    pos = offset + 2
    end = offset + 2 + id_list_size
    
    print(f"IDList Size: {id_list_size}")
    
    while pos < end - 2:
        item_size = struct.unpack_from("<H", lnk_data, pos)[0]
        if item_size == 0:
            break
        item_data = lnk_data[pos:pos+item_size]
        print(f"Item size: {item_size}, hex: {item_data.hex()}")
        if len(item_data) >= 3:
            class_type = item_data[2]
            print(f"Class Type: {hex(class_type)}")
            if class_type in (0x23, 0x25, 0x29, 0x2A):
                flags = item_data[4]
                dl = chr(item_data[3]) if 0x41 <= item_data[3] <= 0x5A else '?'
                print(f"Drive Letter: {dl}, Flags: {hex(flags)}")
                if len(item_data) >= 6:
                    print(f"Label Bytes: {item_data[5:]}")
        pos += item_size

dump()
