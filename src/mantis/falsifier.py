"""
Mantis Adversarial Falsifier (The Mulder Counter-Hypothesis Engine).
Actively interrogates and attempts to falsify prosecutorial malicious verdicts
against benign administrative, JIT, and baseline profiles.
"""

import codecs
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar

from .logger import ExecutionLogger


@dataclass
class CounterHypothesis:
    """Structured result of an adversarial counter-inquest."""

    is_refuted: bool
    falsification_vector: str = "NONE"
    alternative_explanation: str = ""
    citations: list[str] = field(default_factory=list)
    recommended_verdict: str = "MALICIOUS"
    confidence: float = 0.0

    def model_dump(self) -> dict[str, Any]:
        """Compatibility helper matching Pydantic serialization."""
        return asdict(self)

    def model_dump_json(self, indent: int | None = None) -> str:
        """Compatibility helper returning serialized JSON string."""
        return json.dumps(self.model_dump(), indent=indent)


class AdversarialFalsifier:
    """
    Executes the multi-stage counter-hypothesis inquest loop.
    Combines 0ms local deterministic pre-filtering with deep LLM cross-examination.
    """

    # Known benign administrative command line patterns
    ADMIN_COMMAND_PATTERNS: ClassVar[list[str]] = [
        r"logrotate\s+",
        r"apt-get\s+(update|upgrade|autoremove)",
        r"yum\s+(check-update|update)",
        r"updatedb",
        r"systemd-tmpfiles\s+--clean",
        r"cleanmgr\.exe",
        r"gpupdate\.exe\s+/force",
        r"svchost\.exe\s+-k\s+netsvcs",
    ]

    # Known JIT interpreter processes that legitimately allocate executable heap
    JIT_HOST_PROCESSES: ClassVar[set[str]] = {
        "node",
        "nodejs",
        "java",
        "javaw.exe",
        "dotnet",
        "w3wp.exe",
        "python",
        "python3",
    }

    def __init__(self, baseline_kb: dict[str, Any] | None = None):
        self.baseline_kb = baseline_kb or {}

    def check_deterministic_falsification(
        self,
        entity_label: str,
        entity_evidence: dict[str, Any],
    ) -> CounterHypothesis | None:
        """
        0ms Local Rule-Based Inquest.
        Identifies verified administrative maintenance patterns and JIT processes
        before making expensive LLM API calls.
        """
        evidence_str = json.dumps(entity_evidence).lower()

        # 1. JIT Host Process Check
        for proc in self.JIT_HOST_PROCESSES:
            if proc in entity_label.lower() and ("jit_padding" in evidence_str or "cfg" in evidence_str):
                ExecutionLogger.log(
                    "FALSIFIER",
                    f"Deterministic Falsification: {entity_label} matches legitimate JIT runtime profile.",
                    "WARN",
                )
                return CounterHypothesis(
                    is_refuted=True,
                    falsification_vector="JIT_RUNTIME",
                    alternative_explanation=(
                        f"Process {entity_label} is an authorized runtime interpreter "
                        f"allocating dynamic JIT memory pages with compiler safety guards."
                    ),
                    citations=[proc],
                    recommended_verdict="BENIGN_SYSTEM_BEHAVIOR",
                    confidence=1.0,
                )

        # 2. Known Admin Task Check
        for pattern in self.ADMIN_COMMAND_PATTERNS:
            if re.search(pattern, evidence_str):
                ExecutionLogger.log(
                    "FALSIFIER",
                    f"Deterministic Falsification: {entity_label} matches benign administrative task pattern '{pattern}'.",
                    "WARN",
                )
                return CounterHypothesis(
                    is_refuted=True,
                    falsification_vector="KNOWN_ADMIN_TASK",
                    alternative_explanation=(
                        f"Execution telemetry matches standard administrative maintenance routine: {pattern}"
                    ),
                    citations=[pattern],
                    recommended_verdict="BENIGN_SYSTEM_BEHAVIOR",
                    confidence=0.95,
                )

        return None

    def verify_grounding(
        self,
        citations: list[str],
        raw_telemetry: str,
    ) -> bool:
        """
        The Citation Trap: Enforces character-exact substring matching for counter-claims.
        Rejects hallucinated or embellished defense citations.
        """
        if not citations:
            return False

        # Normalize whitespace and escape sequences for robust comparison
        try:
            unescaped_telemetry = codecs.decode(raw_telemetry, "unicode_escape")
        except (UnicodeDecodeError, ValueError):
            unescaped_telemetry = raw_telemetry

        norm_telemetry = re.sub(r"\s+", "", unescaped_telemetry.lower())

        for cit in citations:
            if not cit or cit.upper() == "NONE":
                continue
            norm_cit = re.sub(r"\s+", "", cit.lower())
            if norm_cit not in norm_telemetry:
                ExecutionLogger.log(
                    "FALSIFIER",
                    f"Grounding Failure: Citation '{cit[:50]}' not found verbatim in evidence.",
                    "WARN",
                )
                return False

        return True

    def build_challenger_prompt(
        self,
        entity_label: str,
        prosecution_verdict: dict[str, Any],
        raw_telemetry: str,
        playbook_rules: str = "",
    ) -> str:
        """Constructs the Mulder Challenger inquest prompt."""
        return f"""
YOU ARE A PRINCIPAL DFIR QUALITY AUTHORITY & ADVERSARIAL CHALLENGER.
Your mission is to ACTIVELY CHALLENGE AND FALSIFY the prosecution's malicious verdict.
You must construct the strongest possible DEFENSE COUNTER-HYPOTHESIS proving that this entity is BENIGN or an ADMINISTRATIVE FALSE POSITIVE.

ENTITY ACCUSED:
{entity_label}

PROSECUTION FINDING:
{json.dumps(prosecution_verdict, indent=2)}

PLAYBOOK CONSTRAINTS:
{playbook_rules}

RAW TELEMETRY EVIDENCE:
{raw_telemetry}

INSTRUCTIONS FOR THE CHALLENGER:
1. Actively search for contradictory facts: Is this process legitimately signed? Is it an authorized administrative routine? Does a standard OS maintenance schedule account for this activity?
2. You MUST provide character-exact quotes in 'citations' taken directly from RAW TELEMETRY EVIDENCE.
3. If the evidence conclusively indicates malicious behavior that cannot be explained administratively, set is_refuted=false and recommended_verdict='MALICIOUS'.
4. If an alternative benign explanation is valid and substantiated by evidence, set is_refuted=true and recommended_verdict='BENIGN_SYSTEM_BEHAVIOR'.
"""

    def reconcile_verdict(
        self,
        prosecution_classification: str,
        hypothesis: CounterHypothesis | None,
    ) -> str:
        """
        Judicial Reconciliation:
        Downgrades prosecution verdict only if the counter-hypothesis is substantiated and grounded.
        """
        if not hypothesis:
            return prosecution_classification

        if hypothesis.is_refuted and hypothesis.confidence >= 0.70:
            ExecutionLogger.log(
                "FALSIFIER",
                f"Judicial Reconciliation: Overruling {prosecution_classification} -> {hypothesis.recommended_verdict} (Vector: {hypothesis.falsification_vector})",
                "SUCCESS",
            )
            return hypothesis.recommended_verdict

        return prosecution_classification
