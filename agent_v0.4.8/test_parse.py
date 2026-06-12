import sys
from lnk_parser import parse_lnk_shell_items

img_path = "/media/analyst/external_drive/project_data/cfreds/cfreds_2015_data_leakage_pc.dd"
res = parse_lnk_shell_items("71947", img_path)
print(res)
