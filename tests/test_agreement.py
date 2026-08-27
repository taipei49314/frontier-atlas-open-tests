from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from atlas_test.agreement import score_agreement
from atlas_test.canonical import ProtocolError
from tests.helpers import make_annotation, make_case, write_jsonl, write_packet


class AgreementTests(unittest.TestCase):
    def test_perfect_mixed_agreement_passes_with_high_risk_strata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            safe_case = make_case(assignment_id="safe", case_ref="safe-case")
            unsafe_case = make_case(assignment_id="unsafe", case_ref="unsafe-case")
            _, packet = write_packet(root, [safe_case, unsafe_case])
            annotations = root / "annotations.jsonl"
            rows = [
                make_annotation(
                    assignment_id="safe", contributor_id="a", case=safe_case
                ),
                make_annotation(
                    assignment_id="safe", contributor_id="b", case=safe_case
                ),
                make_annotation(
                    assignment_id="unsafe",
                    contributor_id="a",
                    unsafe=True,
                    case=unsafe_case,
                ),
                make_annotation(
                    assignment_id="unsafe",
                    contributor_id="b",
                    unsafe=True,
                    case=unsafe_case,
                ),
            ]
            write_jsonl(annotations, rows)
            strata = root / "strata.jsonl"
            write_jsonl(
                strata,
                [
                    {
                        "assignment_id": "safe",
                        "severity": "high",
                        "slices": ["control"],
                    },
                    {
                        "assignment_id": "unsafe",
                        "severity": "critical",
                        "slices": ["semantic-shift"],
                    },
                ],
            )
            result = score_agreement(annotations, packet=packet, strata_path=strata)
            self.assertEqual(result["overall"]["verdict"]["kappa_basis_points"], 10000)
            self.assertEqual(
                result["overall"]["violations"]["macro_f1_basis_points"], 10000
            )
            self.assertEqual(result["unsafe_high_critical"]["denominator"], 2)
            self.assertTrue(result["all_gates_pass"])
            self.assertFalse(result["promotion_eligible"])

    def test_same_contributor_and_missing_pair_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case = make_case()
            _, packet = write_packet(root, [case])
            path = root / "annotations.jsonl"
            write_jsonl(
                path,
                [
                    make_annotation(contributor_id="a", case=case),
                    make_annotation(contributor_id="a", case=case),
                ],
            )
            with self.assertRaisesRegex(ProtocolError, "reuses contributor"):
                score_agreement(path, packet=packet)
            write_jsonl(path, [make_annotation(case=case)])
            with self.assertRaisesRegex(ProtocolError, "exactly two"):
                score_agreement(path, packet=packet)

    def test_single_class_kappa_and_missing_strata_are_not_measured(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case_one = make_case(assignment_id="one", case_ref="one-case")
            case_two = make_case(assignment_id="two", case_ref="two-case")
            _, packet = write_packet(root, [case_one, case_two])
            path = root / "annotations.jsonl"
            write_jsonl(
                path,
                [
                    make_annotation(
                        assignment_id="one", contributor_id="a", case=case_one
                    ),
                    make_annotation(
                        assignment_id="one", contributor_id="b", case=case_one
                    ),
                    make_annotation(
                        assignment_id="two", contributor_id="a", case=case_two
                    ),
                    make_annotation(
                        assignment_id="two", contributor_id="b", case=case_two
                    ),
                ],
            )
            result = score_agreement(path, packet=packet)
            self.assertEqual(result["overall"]["verdict"]["status"], "not_measured")
            self.assertEqual(result["unsafe_high_critical"]["status"], "not_measured")
            self.assertFalse(result["gates"]["verdict_kappa_overall"])
            self.assertFalse(result["all_gates_pass"])


if __name__ == "__main__":
    unittest.main()
