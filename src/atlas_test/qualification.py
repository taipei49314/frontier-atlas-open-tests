"""Hidden-key qualification scoring with aggregate-only output."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import (
    PROTOCOL_VERSION,
    ProtocolError,
    contained_path,
    expect_bool,
    expect_enum,
    expect_exact_fields,
    expect_identifier,
    expect_int,
    expect_object,
    expect_sha256,
    file_sha256,
    load_jsonl,
)
from .validation import (
    VERDICTS,
    VIOLATIONS,
    PacketContext,
    validate_annotation_for_case,
)


def score_qualification(
    key_manifest: Any,
    *,
    base_dir: Path,
    submission_path: Path,
    packet: PacketContext,
) -> dict[str, Any]:
    key = expect_object(key_manifest, "qualification_key")
    expect_exact_fields(
        key,
        {
            "schema_version",
            "protocol_version",
            "qualification_id",
            "answer_count",
            "answers_file",
            "answers_sha256",
            "policy",
        },
        "qualification_key",
    )
    if (
        expect_int(key["schema_version"], "qualification_key.schema_version", minimum=1)
        != 1
    ):
        raise ProtocolError("unsupported qualification key schema_version")
    if key["protocol_version"] != PROTOCOL_VERSION:
        raise ProtocolError("unsupported qualification key protocol_version")
    qualification_id = expect_identifier(
        key["qualification_id"], "qualification_key.qualification_id"
    )
    count = expect_int(key["answer_count"], "qualification_key.answer_count", minimum=1)
    answers_path = contained_path(
        base_dir, key["answers_file"], "qualification_key.answers_file"
    )
    expected_hash = expect_sha256(
        key["answers_sha256"], "qualification_key.answers_sha256"
    )
    if file_sha256(answers_path) != expected_hash:
        raise ProtocolError("qualification answer key hash mismatch")
    policy = expect_object(key["policy"], "qualification_key.policy")
    expect_exact_fields(
        policy,
        {
            "min_verdict_basis_points",
            "min_unsafe_basis_points",
            "min_violation_basis_points",
            "critical_must_all_pass",
        },
        "qualification_key.policy",
    )
    thresholds = {
        name: expect_int(policy[name], f"qualification_key.policy.{name}")
        for name in (
            "min_verdict_basis_points",
            "min_unsafe_basis_points",
            "min_violation_basis_points",
        )
    }
    if any(value > 10_000 for value in thresholds.values()):
        raise ProtocolError("qualification thresholds cannot exceed 10000 basis points")
    critical_required = expect_bool(
        policy["critical_must_all_pass"],
        "qualification_key.policy.critical_must_all_pass",
    )
    raw_answers = load_jsonl(answers_path)
    if len(raw_answers) != count:
        raise ProtocolError("qualification answer_count mismatch")
    answers: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_answers):
        name = f"qualification answer[{index}]"
        answer = expect_object(raw, name)
        expect_exact_fields(
            answer,
            {
                "assignment_id",
                "expected_verdict",
                "expected_unsafe_to_clear",
                "expected_violations",
                "critical",
            },
            name,
        )
        assignment_id = expect_identifier(
            answer["assignment_id"], f"{name}.assignment_id"
        )
        if assignment_id in answers:
            raise ProtocolError("duplicate qualification answer assignment_id")
        expect_enum(answer["expected_verdict"], VERDICTS, f"{name}.expected_verdict")
        expect_bool(
            answer["expected_unsafe_to_clear"], f"{name}.expected_unsafe_to_clear"
        )
        if not isinstance(answer["expected_violations"], list):
            raise ProtocolError(f"{name}.expected_violations must be an array")
        normalized = [
            expect_enum(value, VIOLATIONS, f"{name}.expected_violations[]")
            for value in answer["expected_violations"]
        ]
        if len(set(normalized)) != len(normalized):
            raise ProtocolError(f"{name}.expected_violations contains duplicates")
        expect_bool(answer["critical"], f"{name}.critical")
        answers[assignment_id] = answer

    submissions = load_jsonl(submission_path)
    by_assignment: dict[str, dict[str, Any]] = {}
    contributor_ids: set[str] = set()
    for raw in submissions:
        assignment_id = raw.get("assignment_id") if isinstance(raw, dict) else None
        if assignment_id not in packet.cases_by_assignment:
            raise ProtocolError("qualification annotation is outside the bound packet")
        annotation = validate_annotation_for_case(
            raw,
            packet.cases_by_assignment[assignment_id],
            source_contents=packet.source_contents,
        )
        assignment_id = annotation["assignment_id"]
        if assignment_id in by_assignment:
            raise ProtocolError(
                "qualification submission contains duplicate assignment_id"
            )
        by_assignment[assignment_id] = annotation
        contributor_ids.add(annotation["contributor_id"])
    if len(contributor_ids) != 1:
        raise ProtocolError(
            "qualification submission must belong to exactly one contributor"
        )
    if set(by_assignment) != set(answers):
        raise ProtocolError("qualification submission assignment coverage mismatch")
    if set(answers) != set(packet.cases_by_assignment):
        raise ProtocolError("qualification key does not cover the bound packet")

    verdict_correct = 0
    unsafe_correct = 0
    violation_correct = 0
    critical_total = 0
    critical_correct = 0
    for assignment_id, answer in answers.items():
        support = by_assignment[assignment_id]["citation_support"]
        verdict_match = support["verdict"] == answer["expected_verdict"]
        unsafe_match = support["unsafe_to_clear"] == answer["expected_unsafe_to_clear"]
        violation_match = set(support["violations"]) == set(
            answer["expected_violations"]
        )
        verdict_correct += int(verdict_match)
        unsafe_correct += int(unsafe_match)
        violation_correct += int(violation_match)
        if answer["critical"]:
            critical_total += 1
            critical_correct += int(verdict_match and unsafe_match and violation_match)
    if critical_required and critical_total == 0:
        raise ProtocolError("qualification requires at least one critical answer")
    scores = {
        "verdict_basis_points": verdict_correct * 10_000 // count,
        "unsafe_basis_points": unsafe_correct * 10_000 // count,
        "violation_basis_points": violation_correct * 10_000 // count,
    }
    passed = (
        scores["verdict_basis_points"] >= thresholds["min_verdict_basis_points"]
        and scores["unsafe_basis_points"] >= thresholds["min_unsafe_basis_points"]
        and scores["violation_basis_points"] >= thresholds["min_violation_basis_points"]
        and (not critical_required or critical_correct == critical_total)
    )
    return {
        "qualification_id": qualification_id,
        "contributor_id": next(iter(contributor_ids)),
        "answer_count": count,
        "scores": scores,
        "thresholds": thresholds,
        "critical_total": critical_total,
        "critical_correct": critical_correct,
        "passed": passed,
        "answer_details_disclosed": False,
    }
