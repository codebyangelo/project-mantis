"""
Project Mantis: Autonomous DFIR Framework
"""

__version__ = "0.5.5"
__author__ = "Angelo Ayton"

from .courtroom import CourtroomScriptGenerator
from .exceptions import (
    MantisBoundaryError,
    MantisError,
    MantisInvalidBootSignatureError,
    MantisOutOfBoundsPartitionError,
    MantisR2Error,
    MantisReconstructionError,
    MantisTruncatedBlockError,
)
from .extractor import (
    ClampedStreamReader,
    invalidate_evidence_cache,
    validate_sector_bounds,
)
from .falsifier import AdversarialFalsifier, CounterHypothesis

__all__ = [
    "AdversarialFalsifier",
    "ClampedStreamReader",
    "CounterHypothesis",
    "CourtroomScriptGenerator",
    "MantisBoundaryError",
    "MantisError",
    "MantisInvalidBootSignatureError",
    "MantisOutOfBoundsPartitionError",
    "MantisR2Error",
    "MantisReconstructionError",
    "MantisTruncatedBlockError",
    "__author__",
    "__version__",
    "invalidate_evidence_cache",
    "validate_sector_bounds",
]
