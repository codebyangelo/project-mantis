"""
Project Mantis: Autonomous DFIR Framework
"""

import os
import sys

# Ensure package directory is on path for flat submodule imports
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)

__version__ = "0.5.5"
__author__ = "Angelo Ayton"
