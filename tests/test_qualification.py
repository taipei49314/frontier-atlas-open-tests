from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from atlas_test.canonical import PROTOCOL_VERSION, ProtocolError, file_sha256
from atlas_test.qualification import score_qualification
from atlas_test.validation import PacketContext
from tests.helpers import make_annotation, make_case, write_jsonl, write_packet


class QualificationTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[dict, Path, PacketContext, dict[str, dict]]:
        cases = {
            "assign-safe": make_case(assignment_id="assign-safe", case_ref="safe-case"),
            "assign-critical": make_case(
                assignment_id="assign-critical", case_ref="critical-case"
            ),
        }
        _, packet = write_packet(
            root,
            list(cases.values()),
            packet_id="qualification-packet-v1",
            purpose="qualification",
        )
        answers = root / "answers.jsonl"
        write_jsonl(
            answers,
            [
                {
                    "assignment_id": "assign-safe",
                    "expected_verdict": "entails",
                    "expected_unsafe_to_clear": False,
                    "expected_violations": [],
                    "critical": False,
                },
                {
                    "assignment_id": "assign-critical",
                    "expected_verdict": "partial_support",
                    "expected_unsafe_to_clear": True,
                    "expected_violations": ["semantic_shift"],
                    "critical": True,
                },
            ],
        )
        manifest = {
            "schema_version": 1,
            "protocol_version": PROTOCOL_VERSION,
            "qualification_id": "qualification-v1",
            "answer_count": 2,
            "answers_file": "answers.jsonl",
            "answers_sha256": file_sha256(answers),
            "policy": {
                "min_verdict_basis_points": 8000,
                "min_unsafe_basis_points": 9500,
                "min_violation_basis_points": 8000,
                "critical_must_all_pass": True,
            },
        }
        submission = root / "submission.jsonl"
        return manifest, submission, packet, cases

    def test_pass_and_aggregate_only_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key, submission, packet, cases = self._fixture(root)
            write_jsonl(
                submission,
                [
                    make_annotation(
                        assignment_id="assign-safe", case=cases["assign-safe"]
                    ),
                    make_annotation(
                        assignment_id="assign-critical",
                        unsafe=True,
                        case=cases["assign-critical"],
                    ),
                ],
            )
            result = score_qualification(
                key, base_dir=root, submission_path=submission, packet=packet
            )
            self.assertTrue(result["passed"])
            self.assertFalse(result["answer_details_disclosed"])
            self.assertNotIn("answers", result)

    def test_critical_error_fails_and_coverage_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key, submission, packet, cases = self._fixture(root)
            write_jsonl(
                submission,
                [
                    make_annotation(
                        assignment_id="assign-safe", case=cases["assign-safe"]
                    ),
                    make_annotation(
                        assignment_id="assign-critical", case=cases["assign-critical"]
                    ),
                ],
            )
            result = score_qualification(
                key, base_dir=root, submission_path=submission, packet=packet
            )
            self.assertFalse(result["passed"])
            write_jsonl(
                submission,
                [
                    make_annotation(
                        assignment_id="assign-safe", case=cases["assign-safe"]
                    )
                ],
            )
            with self.assertRaisesRegex(ProtocolError, "coverage"):
                score_qualification(
                    key, base_dir=root, submission_path=submission, packet=packet
                )


if __name__ == "__main__":
    unittest.main()
