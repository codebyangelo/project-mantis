"""
Unit test suite proving the deterministic sieve against all 5 Malfind allocation variants.
"""

import os
import sys
import unittest

# Ensure src/ is on sys.path
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from mantis.sieve_deterministic import AllocationType, MalfindClassifier
from tests.fixtures.synthetic_malfind import (
    make_cfg_allocation,
    make_defender_emulation_allocation,
    make_jit_padding_allocation,
    make_trampoline_allocation,
    make_unknown_shellcode_allocation,
)


class TestSieveDeterministicMatrix(unittest.TestCase):
    def test_trampoline_classification(self):
        alloc = make_trampoline_allocation()
        alloc_type = MalfindClassifier.classify_allocation(alloc)
        self.assertEqual(alloc_type, AllocationType.TRAMPOLINE)

        verdict = MalfindClassifier.evaluate_process([alloc])
        self.assertEqual(verdict.verdict, "MALICIOUS")
        self.assertEqual(verdict.confidence, 1.0)
        self.assertTrue(verdict.deterministic)
        self.assertFalse(verdict.requires_llm_audit)
        self.assertEqual(len(verdict.critical_allocations), 1)

    def test_jit_padding_classification(self):
        alloc = make_jit_padding_allocation()
        alloc_type = MalfindClassifier.classify_allocation(alloc)
        self.assertEqual(alloc_type, AllocationType.JIT_PADDING)

        verdict = MalfindClassifier.evaluate_process([alloc])
        self.assertEqual(verdict.verdict, "BENIGN")
        self.assertEqual(verdict.confidence, 1.0)
        self.assertTrue(verdict.deterministic)
        self.assertFalse(verdict.requires_llm_audit)
        self.assertEqual(len(verdict.critical_allocations), 0)

    def test_cfg_classification(self):
        alloc = make_cfg_allocation()
        alloc_type = MalfindClassifier.classify_allocation(alloc)
        self.assertEqual(alloc_type, AllocationType.CFG)

        verdict = MalfindClassifier.evaluate_process([alloc])
        self.assertEqual(verdict.verdict, "BENIGN")
        self.assertEqual(verdict.confidence, 1.0)
        self.assertTrue(verdict.deterministic)
        self.assertFalse(verdict.requires_llm_audit)

    def test_defender_emulation_classification(self):
        alloc = make_defender_emulation_allocation()
        alloc_type = MalfindClassifier.classify_allocation(alloc)
        self.assertEqual(alloc_type, AllocationType.DEFENDER_EMULATION)

        verdict = MalfindClassifier.evaluate_process([alloc])
        self.assertEqual(verdict.verdict, "BENIGN")
        self.assertEqual(verdict.confidence, 1.0)
        self.assertFalse(verdict.requires_llm_audit)

    def test_unknown_shellcode_triggers_llm_audit(self):
        alloc = make_unknown_shellcode_allocation()
        alloc_type = MalfindClassifier.classify_allocation(alloc)
        self.assertEqual(alloc_type, AllocationType.UNKNOWN)

        verdict = MalfindClassifier.evaluate_process([alloc])
        self.assertEqual(verdict.verdict, "NEEDS_REVIEW")
        self.assertEqual(verdict.confidence, 0.5)
        self.assertTrue(verdict.requires_llm_audit)

    def test_mixed_allocations_trampoline_precedence(self):
        """Proves that a malicious trampoline takes absolute precedence over benign JIT allocations."""
        jit_alloc = make_jit_padding_allocation(pid=9999, process_name="injected_worker.exe")
        tramp_alloc = make_trampoline_allocation(pid=9999, process_name="injected_worker.exe")

        verdict = MalfindClassifier.evaluate_process([jit_alloc, tramp_alloc])
        self.assertEqual(verdict.verdict, "MALICIOUS")
        self.assertEqual(verdict.confidence, 1.0)
        self.assertFalse(verdict.requires_llm_audit)
        self.assertEqual(len(verdict.critical_allocations), 1)

    def test_empty_allocations_fail_closed_benign(self):
        verdict = MalfindClassifier.evaluate_process([])
        self.assertEqual(verdict.verdict, "BENIGN")
        self.assertEqual(verdict.confidence, 1.0)
        self.assertFalse(verdict.requires_llm_audit)


if __name__ == "__main__":
    unittest.main()
