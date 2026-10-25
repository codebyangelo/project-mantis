"""
Project Mantis: Autonomous DFIR Framework
"""

__version__ = "0.5.5"
__author__ = "Angelo Ayton"

from .exceptions import (
    MantisError,
    MantisBoundaryError,
    MantisTruncatedBlockError,
    MantisInvalidBootSignatureError,
    MantisOutOfBoundsPartitionError,
    MantisR2Error,
    MantisReconstructionError,
)
from .extractor import (
    validate_sector_bounds,
    invalidate_evidence_cache,
    ClampedStreamReader,
)

__all__ = [
    "__version__",
    "__author__",
    "MantisError",
    "MantisBoundaryError",
    "MantisTruncatedBlockError",
    "MantisInvalidBootSignatureError",
    "MantisOutOfBoundsPartitionError",
    "MantisR2Error",
    "MantisReconstructionError",
    "validate_sector_bounds",
    "invalidate_evidence_cache",
    "ClampedStreamReader",
]
