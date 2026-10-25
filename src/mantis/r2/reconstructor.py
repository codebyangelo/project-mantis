"""
Mantis Dumped Binary Reconstructor.
Implements memory-to-disk PE/ELF section re-alignment using rabin2 section mutation (radare2 Issue #15449).
"""

import shutil
from pathlib import Path

from ..exceptions import MantisR2Error, MantisReconstructionError
from .wrapper import R2Wrapper


def reconstruct_dumped_pe(
    dump_path: str | Path,
    output_path: str | Path,
    wrapper: R2Wrapper | None = None,
) -> bool:
    """
    Invokes rabin2 to re-align virtual sections and synchronize header offsets for memory dumps.
    Uses 'rabin2 -O r' (section resize/re-align) and '-O p' (permission patch).

    Preserves original evidence by creating the reconstructed binary at output_path.
    Fails closed if rabin2 fails or output lacks valid executable headers.
    """
    src = Path(dump_path)
    dst = Path(output_path)

    if not src.exists():
        raise MantisReconstructionError(f"Source memory dump not found: {src}")

    if src.stat().st_size == 0:
        raise MantisReconstructionError(f"Source memory dump is empty (0 bytes): {src}")

    r2 = wrapper or R2Wrapper()
    if not r2.rabin2_bin:
        raise MantisReconstructionError("rabin2 executable is required for binary section repair.")

    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)

        cmd = [r2.rabin2_bin, "-O", "r", "-O", "p", str(dst)]
        r2.run_command(cmd, timeout=30, check=True)

        # Post-condition verification: check magic header
        with open(dst, "rb") as f:
            header = f.read(4)

        if not header.startswith((b"MZ", b"\x7fELF")):
            raise MantisReconstructionError(
                f"Reconstructed binary at {dst} lacks valid PE (MZ) or ELF magic header: {header.hex()}"
            )

        return True
    except MantisR2Error as e:
        raise MantisReconstructionError(f"rabin2 section repair failed: {e}") from e
    except Exception as e:
        if isinstance(e, MantisReconstructionError):
            raise
        raise MantisReconstructionError(f"Section reconstruction unexpected failure: {e}") from e
