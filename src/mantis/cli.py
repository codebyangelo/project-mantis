"""
Project Mantis CLI.
Unified command-line interface for autonomous DFIR triage, evidence carving,
dump analysis, and Model Context Protocol (MCP) server execution.
"""

import argparse
import json
import sys
from typing import Any

from .exceptions import MantisR2Error
from .falsifier import AdversarialFalsifier
from .logger import ExecutionLogger
from .sieve_deterministic import MalfindAllocation, MalfindClassifier


def cmd_triage(args: argparse.Namespace) -> int:
    """Dispatches offline or live triage to the orchestrator engine."""
    from .orchestrator import main as orchestrator_main

    # Build argv forwarded to orchestrator
    fwd_args = []
    if getattr(args, "deep", False):
        fwd_args.append("--deep")
    if getattr(args, "live", False):
        fwd_args.append("--live")
    if getattr(args, "interval", None):
        fwd_args.extend(["--interval", str(args.interval)])

    sys_argv_backup = list(sys.argv)
    try:
        sys.argv = ["mantis triage"] + fwd_args
        orchestrator_main()
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
    finally:
        sys.argv = sys_argv_backup


def cmd_carve(args: argparse.Namespace) -> int:
    """Dispatches evidence extraction and carving to the extractor engine."""
    from .extractor import main as extractor_main

    fwd_args = []
    if getattr(args, "deep", False):
        fwd_args.append("--deep")
    if getattr(args, "memory", False):
        fwd_args.append("--memory")
    if getattr(args, "disk", False):
        fwd_args.append("--disk")
    if getattr(args, "registry", False):
        fwd_args.append("--registry")
    if getattr(args, "evtx", False):
        fwd_args.append("--evtx")
    if getattr(args, "prefetch", False):
        fwd_args.append("--prefetch")
    if getattr(args, "lnk", False):
        fwd_args.append("--lnk")
    if getattr(args, "pcap", False):
        fwd_args.append("--pcap")

    sys_argv_backup = list(sys.argv)
    try:
        sys.argv = ["mantis carve"] + fwd_args
        extractor_main()
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 0
    finally:
        sys.argv = sys_argv_backup


def cmd_analyze_dump(args: argparse.Namespace) -> int:
    """
    Performs standalone deterministic analysis on a memory dump or carved allocation.
    Evaluates assembly instructions and checks adversarial false-positive refutations.
    """
    dump_path = args.dump
    target_pid = getattr(args, "pid", None) or 1000
    emit_json = getattr(args, "json", False)

    try:
        with open(dump_path, "rb") as f:
            raw_bytes = f.read(4096)
    except OSError as e:
        ExecutionLogger.log("CLI", f"Failed to read dump file: {e}", "ERROR")
        if emit_json:
            print(json.dumps({"error": str(e), "status": "failed"}))
        return 1

    # Disassemble if r2 is available
    disasm_lines = []
    try:
        from .r2.wrapper import R2Wrapper

        r2 = R2Wrapper()
        if r2.r2_bin:
            opcodes = r2.disassemble(dump_path, offset=0, count=20)
            disasm_lines = [op.opcode for op in opcodes if op.opcode]
    except (MantisR2Error, OSError, ValueError) as e:
        ExecutionLogger.log("CLI", f"Disassembly probe bypassed: {e}", "DEBUG")

    # Fallback heuristic if disasm is empty but known byte patterns exist
    if not disasm_lines and raw_bytes.startswith(b"\x48\xb8") and b"\xff\xe0" in raw_bytes[:32]:
        disasm_lines = ["movabs rax, 0x401000", "jmp rax"]

    disasm_str = " ; ".join(disasm_lines)

    # Synthesize allocation and evaluate heuristics
    alloc = MalfindAllocation(
        pid=int(target_pid),
        process_name="analyzed_process",
        start_vpn="0x100000",
        end_vpn="0x101000",
        protection="PAGE_EXECUTE_READWRITE",
        tag="VAD",
        hexdump=raw_bytes[:64].hex(),
        disasm=disasm_str,
    )

    det_type = MalfindClassifier.classify_allocation(alloc)
    falsifier = AdversarialFalsifier()
    refutation = falsifier.check_deterministic_falsification(
        entity_label=f"PID {target_pid} ({alloc.process_name})",
        entity_evidence=alloc.hexdump,
    )

    verdict = "MALICIOUS" if det_type.name in ["TRAMPOLINE", "ROP_STUB", "SHELLCODE"] else "SUSPICIOUS"
    if refutation and refutation.is_refuted:
        verdict = refutation.recommended_verdict

    result: dict[str, Any] = {
        "dump_path": dump_path,
        "pid": target_pid,
        "classification": det_type.name,
        "verdict": verdict,
        "refutation": refutation.alternative_explanation if refutation else None,
        "sample_bytes_hex": raw_bytes[:32].hex(),
    }

    if emit_json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n[+] Mantis Dump Analysis: {dump_path}")
        print(f"    Target PID:      {target_pid}")
        print(f"    Heuristic Type:  {det_type.name}")
        print(f"    Final Verdict:   {verdict}")
        if refutation:
            print(f"    Counter-Inquest: {refutation.alternative_explanation}")

    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    """Runs the Model Context Protocol (MCP) stdio server."""
    from .mcp.server import run_mcp_server

    ExecutionLogger.log("CLI", "Launching Mantis MCP server on stdio...")
    try:
        run_mcp_server()
        return 0
    except KeyboardInterrupt:
        return 0


def build_parser() -> argparse.ArgumentParser:
    """Builds the unified CLI argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="mantis",
        description="Project Mantis: Hardened Autonomous DFIR Platform",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Operational mode")

    # mantis triage
    p_triage = subparsers.add_parser("triage", help="Run offline or live forensic triage")
    p_triage.add_argument("--deep", action="store_true", help="Enable deep forensics (EVTX, Registry, Prefetch)")
    p_triage.add_argument("--live", action="store_true", help="Run in continuous live host monitoring mode")
    p_triage.add_argument("--interval", type=int, default=30, help="Interval in seconds for live telemetry loops")

    # mantis carve
    p_carve = subparsers.add_parser("carve", help="Carve artifacts from memory and disk images")
    p_carve.add_argument("--deep", action="store_true", help="Extract all deep forensics streams")
    p_carve.add_argument("--memory", action="store_true", help="Extract only memory artifacts")
    p_carve.add_argument("--disk", action="store_true", help="Extract disk metadata (bodyfile)")
    p_carve.add_argument("--registry", action="store_true", help="Extract registry artifacts")
    p_carve.add_argument("--evtx", action="store_true", help="Extract EVTX streams")
    p_carve.add_argument("--prefetch", action="store_true", help="Extract Prefetch streams")
    p_carve.add_argument("--lnk", action="store_true", help="Extract LNK streams")
    p_carve.add_argument("--pcap", action="store_true", help="Extract PCAP streams")

    # mantis analyze-dump
    p_analyze = subparsers.add_parser("analyze-dump", help="Analyze raw memory dump or carved allocation")
    p_analyze.add_argument("dump", help="Path to memory dump or raw binary slice")
    p_analyze.add_argument("--pid", type=int, default=1000, help="Target process PID")
    p_analyze.add_argument("--json", action="store_true", help="Output results in JSON format")

    # mantis mcp
    p_mcp = subparsers.add_parser("mcp", help="Run Model Context Protocol (MCP) server")
    p_mcp.add_argument("--transport", default="stdio", choices=["stdio"], help="Transport mechanism")

    return parser


def main(argv: list[str] | None = None) -> int:
    """Main CLI entrypoint supporting both subcommands and backward-compatible flags."""
    args_list = argv if argv is not None else sys.argv[1:]

    # Backwards compatibility: if invoked with legacy flags like 'mantis --deep' or 'mantis --live'
    if args_list and args_list[0] in ["--deep", "--live", "--interval"]:
        args_list = ["triage"] + args_list

    parser = build_parser()
    if not args_list:
        # Default behavior with no arguments: show help
        parser.print_help()
        return 0

    parsed = parser.parse_args(args_list)

    if parsed.subcommand == "triage":
        return cmd_triage(parsed)
    elif parsed.subcommand == "carve":
        return cmd_carve(parsed)
    elif parsed.subcommand == "analyze-dump":
        return cmd_analyze_dump(parsed)
    elif parsed.subcommand == "mcp":
        return cmd_mcp(parsed)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
