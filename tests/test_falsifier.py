"""
Unit test suite for Phase 4: Adversarial Falsifier (Mulder) and Courtroom Code-Mode (Camel).
Tests 0ms deterministic falsification, citation grounding, judicial reconciliation,
and standalone Python byte-exact courtroom verification script execution.
"""

import os
import subprocess
import sys
import tempfile
import unittest

# Ensure src/ is on sys.path for test runners executing outside an installed wheel
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from mantis.courtroom import CourtroomScriptGenerator
from mantis.falsifier import AdversarialFalsifier, CounterHypothesis


class TestAdversarialFalsifier(unittest.TestCase):
    """Tests the Mulder-style adversarial counter-hypothesis engine."""

    def setUp(self):
        self.falsifier = AdversarialFalsifier()

    def test_jit_runtime_deterministic_refutation(self):
        evidence = {
            "PID": 4012,
            "ImageFileName": "node",
            "Allocations": [{"tag": "VadS", "protection": "RWX", "type": "jit_padding"}],
        }
        hypothesis = self.falsifier.check_deterministic_falsification(
            entity_label="PID 4012 (node)",
            entity_evidence=evidence,
        )
        self.assertIsNotNone(hypothesis)
        self.assertTrue(hypothesis.is_refuted)
        self.assertEqual(hypothesis.falsification_vector, "JIT_RUNTIME")
        self.assertEqual(hypothesis.recommended_verdict, "BENIGN_SYSTEM_BEHAVIOR")
        self.assertEqual(hypothesis.confidence, 1.0)

    def test_admin_task_deterministic_refutation(self):
        evidence = {
            "PID": 1050,
            "CommandLine": "/usr/sbin/logrotate /etc/logrotate.conf",
        }
        hypothesis = self.falsifier.check_deterministic_falsification(
            entity_label="PID 1050 (logrotate)",
            entity_evidence=evidence,
        )
        self.assertIsNotNone(hypothesis)
        self.assertTrue(hypothesis.is_refuted)
        self.assertEqual(hypothesis.falsification_vector, "KNOWN_ADMIN_TASK")
        self.assertEqual(hypothesis.recommended_verdict, "BENIGN_SYSTEM_BEHAVIOR")

    def test_unknown_malicious_not_refuted(self):
        evidence = {
            "PID": 6666,
            "ImageFileName": "svchost_injected.exe",
            "Allocations": [{"hexdump": "48 b8 78 56 34 12 fd 7f ff e0"}],
        }
        hypothesis = self.falsifier.check_deterministic_falsification(
            entity_label="PID 6666 (svchost_injected.exe)",
            entity_evidence=evidence,
        )
        self.assertIsNone(hypothesis)

    def test_grounding_exact_substring_verification(self):
        raw_telemetry = '{"Process": "apt-get", "Args": "update -y", "PID": 8888}'
        # Verbatim match
        self.assertTrue(
            self.falsifier.verify_grounding(
                citations=["apt-get", "update -y"],
                raw_telemetry=raw_telemetry,
            )
        )
        # Hallucinated string not in raw telemetry
        self.assertFalse(
            self.falsifier.verify_grounding(
                citations=["unsubstantiated_c2_domain.com"],
                raw_telemetry=raw_telemetry,
            )
        )
        # Empty citations
        self.assertFalse(
            self.falsifier.verify_grounding(
                citations=[],
                raw_telemetry=raw_telemetry,
            )
        )

    def test_judicial_reconciliation_overrule(self):
        hypothesis = CounterHypothesis(
            is_refuted=True,
            falsification_vector="KNOWN_ADMIN_TASK",
            alternative_explanation="Verified cron job",
            citations=["logrotate"],
            recommended_verdict="BENIGN_SYSTEM_BEHAVIOR",
            confidence=0.95,
        )
        reconciled = self.falsifier.reconcile_verdict("MALICIOUS", hypothesis)
        self.assertEqual(reconciled, "BENIGN_SYSTEM_BEHAVIOR")

    def test_judicial_reconciliation_stands_when_unrefuted(self):
        hypothesis = CounterHypothesis(
            is_refuted=False,
            falsification_vector="NONE",
            alternative_explanation="No exculpatory evidence found",
            citations=[],
            recommended_verdict="MALICIOUS",
            confidence=0.1,
        )
        reconciled = self.falsifier.reconcile_verdict("MALICIOUS", hypothesis)
        self.assertEqual(reconciled, "MALICIOUS")


class TestCourtroomScriptGenerator(unittest.TestCase):
    """Tests Camel-style executable courtroom verification scripts."""

    def test_script_syntax_compilation(self):
        script = CourtroomScriptGenerator.generate_reproduction_script(
            evidence_file="test_image.raw",
            offset=0x1000,
            expected_hex="48b8",
            sample_size=32,
            entity_label="PID 1337",
            rule_name="Process Injection",
        )
        # Must be valid Python code
        compiled = compile(script, "<test>", "exec")
        self.assertIsNotNone(compiled)

    def test_script_execution_against_synthetic_evidence(self):
        # Create a synthetic 1KB evidence file with a known hex pattern at offset 256 (0x100)
        with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as ev_file:
            ev_file.write(b"\x90" * 256)
            # Inject malicious movabs rax, addr (48 b8 ...)
            ev_file.write(bytes.fromhex("48b878563412fd7f0000ffe0"))
            ev_file.write(b"\x00" * 512)
            ev_path = ev_file.name

        try:
            script_content = CourtroomScriptGenerator.generate_reproduction_script(
                evidence_file=ev_path,
                offset=256,
                expected_hex="48b878563412fd7f",
                sample_size=16,
                entity_label="PID 9999",
                rule_name="Trampoline Injection",
            )

            # Write script to temporary executable file and run it
            with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as script_file:
                script_file.write(script_content)
                script_path = script_file.name

            try:
                proc = subprocess.run(
                    [sys.executable, script_path],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(proc.returncode, 0, f"Script failed: {proc.stderr}")
                self.assertIn("Courtroom Admissible Proof Confirmed", proc.stdout)
                self.assertIn("0x100", proc.stdout)
            finally:
                if os.path.exists(script_path):
                    os.remove(script_path)
        finally:
            if os.path.exists(ev_path):
                os.remove(ev_path)

    def test_script_fails_closed_on_tampered_evidence(self):
        with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as ev_file:
            ev_file.write(b"\x00" * 512)
            ev_path = ev_file.name

        try:
            script_content = CourtroomScriptGenerator.generate_reproduction_script(
                evidence_file=ev_path,
                offset=128,
                expected_hex="48b8",
                sample_size=16,
            )

            with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as script_file:
                script_file.write(script_content)
                script_path = script_file.name

            try:
                proc = subprocess.run(
                    [sys.executable, script_path],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                # Exit code 3 is mismatch
                self.assertEqual(proc.returncode, 3)
                self.assertIn("[!] MISMATCH", proc.stdout)
            finally:
                if os.path.exists(script_path):
                    os.remove(script_path)
        finally:
            if os.path.exists(ev_path):
                os.remove(ev_path)

    def test_code_mode_section_generation(self):
        findings = [
            {
                "pid": "PID 1337",
                "offset": 0x4000,
                "expected_hex": "48b8",
                "evidence_file": "sample.raw",
            }
        ]
        section = CourtroomScriptGenerator.generate_code_mode_section(findings)
        self.assertIn("## 8. Courtroom Admissibility", section)
        self.assertIn("PID 1337", section)
        self.assertIn("```python", section)


if __name__ == "__main__":
    unittest.main()
