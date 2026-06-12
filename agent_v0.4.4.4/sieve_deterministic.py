"""
Deterministic classification layer for Project Mantis v0.4.4
Inserts between SMPT and Orchestrator. No LLM involvement.
"""

from dataclasses import dataclass
from enum import Enum
import re
from typing import List, Optional

class AllocationType(Enum):
    CFG = "cfg"                          # movabs rax, addr; sub rcx, rax (no jump)
    JIT_PADDING = "jit_padding"          # jmp nearby; add [rax],al; int3 sled
    TRAMPOLINE = "trampoline"            # movabs rax, addr; jmp rax (arbitrary redirect)
    DEFENDER_EMULATION = "defender"      # jmp rdx; int3 (MsMpEng.exe only)
    UNKNOWN = "unknown"

@dataclass
class MalfindAllocation:
    start_vpn: str
    end_vpn: str
    protection: str
    tag: str
    disasm: str
    hexdump: str
    process_name: str
    pid: int

@dataclass
class ProcessVerdict:
    pid: int
    process_name: str
    verdict: str  # "MALICIOUS", "BENIGN", "NEEDS_REVIEW"
    confidence: float
    deterministic: bool
    reasoning: str
    critical_allocations: List[dict]
    benign_allocations: List[dict]
    requires_llm_audit: bool

class MalfindClassifier:
    # Pattern 1: Malicious trampoline - redirect to arbitrary address
    TRAMPOLINE_RE = re.compile(
        r'movabs\s+rax,\s*(0x[0-9a-f]+)\s*;\s*(?:0x[0-9a-f]+:\s*)?jmp\s+rax',
        re.IGNORECASE
    )
    
    # Pattern 2: Benign JIT - jump to nearby code, then padding
    JIT_RE = re.compile(
        r'jmp\s+(0x[0-9a-f]+)\s*;\s*(?:0x[0-9a-f]+:\s*)?add\s+byte\s+ptr\s*\[\s*rax\s*\]\s*,\s*al',
        re.IGNORECASE
    )
    
    # Pattern 3: CFG - arithmetic check, no jump
    CFG_RE = re.compile(
        r'movabs\s+rax,\s*(0x[0-9a-f]+)\s*;\s*(?:0x[0-9a-f]+:\s*)?sub\s+rcx\s*,\s*rax',
        re.IGNORECASE
    )
    
    # Defender pattern: indirect jump through register with int3
    DEFENDER_RE = re.compile(
        r'jmp\s+r[0-9a-z]{1,2}\b',
        re.IGNORECASE
    )
    
    @staticmethod
    def classify_allocation(alloc: MalfindAllocation) -> AllocationType:
        disasm = alloc.disasm.replace('\n', ' ; ').replace('\t', ' ')
        
        # Special case: MsMpEng.exe Defender emulation
        if alloc.process_name.lower() == 'msmpeng.exe':
            if MalfindClassifier.DEFENDER_RE.search(disasm):
                if 'int3' in disasm:
                    return AllocationType.DEFENDER_EMULATION
        
        # Check trampoline first (most specific)
        if MalfindClassifier.TRAMPOLINE_RE.search(disasm):
            return AllocationType.TRAMPOLINE
        
        # Check JIT padding
        if MalfindClassifier.JIT_RE.search(disasm):
            return AllocationType.JIT_PADDING
        
        # Check CFG
        if MalfindClassifier.CFG_RE.search(disasm):
            return AllocationType.CFG
        
        # Heuristic: heavy int3 or add [rax],al padding = JIT
        int3_count = disasm.count('int3')
        add_count = disasm.count('add byte ptr [rax], al')
        if int3_count > 3 or add_count > 2:
            return AllocationType.JIT_PADDING
        
        return AllocationType.UNKNOWN
    
    @classmethod
    def evaluate_process(cls, allocations: List[MalfindAllocation]) -> ProcessVerdict:
        if not allocations:
            return ProcessVerdict(
                pid=0, process_name="", verdict="BENIGN", confidence=1.0,
                deterministic=True, reasoning="No allocations",
                critical_allocations=[], benign_allocations=[], requires_llm_audit=False
            )
        
        pid = allocations[0].pid
        process_name = allocations[0].process_name
        
        classified = [(a, cls.classify_allocation(a)) for a in allocations]
        
        has_trampoline = any(c == AllocationType.TRAMPOLINE for _, c in classified)
        has_defender = any(c == AllocationType.DEFENDER_EMULATION for _, c in classified)
        has_jit = any(c == AllocationType.JIT_PADDING for _, c in classified)
        has_cfg = any(c == AllocationType.CFG for _, c in classified)
        
        # Critical logic: ANY trampoline = MALICIOUS
        # Defender emulation = BENIGN (special case)
        if has_trampoline:
            critical_allocs = [
                {
                    "vpn": a.start_vpn,
                    "pattern": a.disasm[:200],
                    "type": "TRAMPOLINE"
                }
                for a, c in classified if c == AllocationType.TRAMPOLINE
            ]
            return ProcessVerdict(
                pid=pid,
                process_name=process_name,
                verdict="MALICIOUS",
                confidence=1.0,
                deterministic=True,
                reasoning=f"Process {process_name} contains {len(critical_allocs)} allocation(s) with malicious trampoline patterns (movabs rax, addr; jmp rax). Per playbook PROC_INJ_001, this is process injection.",
                critical_allocations=critical_allocs,
                benign_allocations=[],
                requires_llm_audit=False  # Deterministic, no LLM needed
            )
        
        if has_defender and process_name.lower() == 'msmpeng.exe':
            return ProcessVerdict(
                pid=pid,
                process_name=process_name,
                verdict="BENIGN",
                confidence=1.0,
                deterministic=True,
                reasoning="MsMpEng.exe RWX allocations contain Defender emulation patterns (jmp rdx, int3). Per playbook FP_004, this is legitimate behavior.",
                critical_allocations=[],
                benign_allocations=[{"type": "DEFENDER_EMULATION"}],
                requires_llm_audit=False
            )
        
        if has_jit or has_cfg:
            benign_types = []
            if has_jit:
                benign_types.append({"type": "JIT_PADDING"})
            if has_cfg:
                benign_types.append({"type": "CFG"})
            return ProcessVerdict(
                pid=pid,
                process_name=process_name,
                verdict="BENIGN",
                confidence=1.0,
                deterministic=True,
                reasoning=f"Process {process_name} contains only benign patterns: JIT padding and/or CFG checks. No malicious trampolines detected.",
                critical_allocations=[],
                benign_allocations=benign_types,
                requires_llm_audit=False
            )
        
        # Unknown allocations - needs LLM review
        return ProcessVerdict(
            pid=pid,
            process_name=process_name,
            verdict="NEEDS_REVIEW",
            confidence=0.5,
            deterministic=True,
            reasoning=f"Process {process_name} has RWX allocations with unrecognized patterns. Requires LLM evaluation.",
            critical_allocations=[],
            benign_allocations=[{"type": "UNKNOWN", "disasm": a.disasm[:200]} for a, c in classified if c == AllocationType.UNKNOWN],
            requires_llm_audit=True
        )
