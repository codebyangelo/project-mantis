"""
Mantis DFIR Exceptions.
Defines fail-closed forensic boundary and execution exceptions.
"""

MANTIS_RC_SUCCESS = 0
MANTIS_RC_FAILURE = -1
MANTIS_RC_BOUNDARY_VIOLATION = -2
MANTIS_RC_TIMEOUT = -3
MANTIS_RC_SECURITY_VIOLATION = -4


class MantisError(Exception):
    """Base exception for all Mantis runtime and analysis errors."""

    def __init__(self, message: str = "", code: int = MANTIS_RC_FAILURE):
        super().__init__(message)
        self.message = message
        self.code = code

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}" if self.message else f"[{self.code}]"


class MantisBoundaryError(MantisError):
    """Raised when an evidence boundary or memory constraint is violated."""

    def __init__(
        self,
        message: str = "Forensic boundary violation",
        code: int = MANTIS_RC_BOUNDARY_VIOLATION,
    ):
        super().__init__(message=message, code=code)


class MantisTruncatedBlockError(MantisBoundaryError):
    """Raised when a candidate sector is truncated (<512 bytes)."""



class MantisInvalidBootSignatureError(MantisBoundaryError):
    """Raised when an MBR sector lacks the 0x55AA magic trailer."""



class MantisOutOfBoundsPartitionError(MantisBoundaryError):
    """Raised when partition extent exceeds total image boundaries."""



class MantisR2Error(MantisError):
    """Raised when a radare2 / rabin2 / rahash2 CLI process fails."""



class MantisReconstructionError(MantisR2Error):
    """Raised when memory-dump section repair (rabin2 -O) fails."""

