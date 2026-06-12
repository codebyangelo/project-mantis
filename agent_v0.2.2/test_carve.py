import time
from mcp_server import carve_memory_strings

img_path = "/media/analyst/external_drive/project_data/Rocba-Memory.raw"

t0 = time.time()
try:
    res = carve_memory_strings("NETWORK", img_path, "68")
    t1 = time.time()
    print(f"Time taken: {t1 - t0:.2f} seconds")
    print("Result:")
    print(res)
except Exception as e:
    print(f"Error: {e}")
