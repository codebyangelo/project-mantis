import mmap
import time

try:
    # Allocate anonymous RWX memory (PROT_READ | PROT_WRITE | PROT_EXEC)
    rwx_mem = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    
    # Write a classic x86_64 trampoline pattern: movabs rax, 0x1234567890abcdef; jmp rax
    # Hex: \x48\xb8\xef\xcd\xab\x90\x78\x56\x34\x12\xff\xe0
    rwx_mem.write(b"\x48\xb8\xef\xcd\xab\x90\x78\x56\x34\x12\xff\xe0")
    
    print("Simulated process injection threat active. RWX allocated and trampoline pattern written.")
    # Keep the process alive for 5 minutes
    time.sleep(300)
except Exception as e:
    print("Failed to allocate RWX memory:")
    print(e)
