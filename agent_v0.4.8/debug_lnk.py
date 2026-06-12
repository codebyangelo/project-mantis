import subprocess
from new_lnk_parser import parse_lnk_shell_items

# Get inode for [secret_project]_design_concept.LNK
bodyfile = "/mnt/sift_ext4/sift_home/projects/project_mantis/agent_v0.4.8_cfreds/cache/bodyfile_cfreds_desktop.txt"
# Let's just find the file in evidence_dir?
# It's better to find the inode from evidence_cache.
# Evidence dir is /media/analyst/external_drive/project_data
