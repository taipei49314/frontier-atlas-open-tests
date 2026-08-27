"""Two-annotator agreement metrics with explicit gate denominators."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .canonical import (
    ProtocolError,
    expect_enum,
    expect_exact_fields,
    expect_identifier,
    expect_object,
    load_jsonl,
)
from .validation import VIOLATIONS, PacketContext, validate_annotation_for_case


def _basis_points(numerator: int, denominator: int) -> int | None:
    if denominator <= 0:
        return None
    scaled = numerator * 10_000
    if scaled >= 0:
        return (scaled + denominator // 2) // denominator
    return -((-scaled + denominator // 2) // denominator)


def _verdict_metrics(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
) -> dict[str, Any]:
    count = len(pairs)
    if count == 0:
        return {
            "denominator": 0,
            "observed_agreement_basis_points": None,
            "kappa_numerator": None,
            "kappa_denominator": None,
            "kappa_basis_points": None,
            "status": "not_measured",
        }
    verdict_a = [pair[0]["citation_support"]["verdict"] for pair in pairs]
    verdict_b = [pair[1]["citation_support"]["verdict"] for pair in pairs]
    observed_count = sum(left == right for left, right in zip(verdict_a, verdict_b))
    counts_a = Counter(verdict_a)
    counts_b = Counter(verdict_b)
    expected_numerator = sum(
        counts_a[key] * counts_b[key] for key in set(counts_a) | set(counts_b)
    )
    kappa_numerator = observed_count * count - expected_numerator
    kappa_denominator = count * count - expected_numerator
    kappa_bp = _basis_points(kappa_numerator, kappa_denominator)
    return {
        "denominator": count,
        "observed_agreement_basis_points": observed_count * 10_000 // count,
        "kappa_numerator": kappa_numerator,
        "kappa_denominator": kappa_denominator,
        "kappa_basis_points": kappa_bp,
        "status": "measured" if kappa_bp is not None else "not_measured",
    }


def _unsafe_metrics(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
) -> dict[str, Any]:
    count = len(pairs)
    if count == 0:
        return {
            "denominator": 0,
            "raw_agreement_basis_points": None,
            "status": "not_measured",
        }
    agreed = sum(
        left["citation_support"]["unsafe_to_clear"]
        == right["citation_support"]["unsafe_to_clear"]
        for left, right in pairs
    )
    return {
        "denominator": count,
        "raw_agreement_basis_points": agreed * 10_000 // count,
        "status": "measured",
    }


def _violation_metrics(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
) -> dict[str, Any]:
    count = len(pairs)
    per_label: dict[str, dict[str, Any]] = {}
    measured_scores: list[int] = []
    exact_matches = 0
    for left, right in pairs:
        exact_matches += int(
            set(left["citation_support"]["violations"])
            == set(right["citation_support"]["violations"])
        )
    for violation in sorted(VIOLATIONS):
        both_positive = 0
        positive_mismatches = 0
        for left, right in pairs:
            left_has = violation in left["citation_support"]["violations"]
            right_has = violation in right["citation_support"]["violations"]
            both_positive += int(left_has and right_has)
            positive_mismatches += int(left_has != right_has)
        denominator = 2 * both_positive + positive_mismatches
        score = _basis_points(2 * both_positive, denominator)
        if score is not None:
            measured_scores.append(score)
        per_label[violation] = {
            "positive_union_denominator": both_positive + positive_mismatches,
            "f1_basis_points": score,
            "status": "measured" if score is not None else "not_measured",
        }
    macro = (
        (sum(measured_scores) + len(measured_scores) // 2) // len(measured_scores)
        if measured_scores
        else None
    )
    return {
        "assignment_denominator": count,
        "exact_match_basis_points": exact_matches * 10_000 // count if count else None,
        "macro_f1_basis_points": macro,
        "measured_label_count": len(measured_scores),
        "per_label": per_label,
        "status": "measured" if macro is not None else "not_measured",
    }


def _metric_bundle(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
) -> dict[str, Any]:
    return {
        "assignment_count": len(pairs),
        "verdict": _verdict_metrics(pairs),
        "unsafe_to_clear": _unsafe_metrics(pairs),
        "violations": _violation_metrics(pairs),
    }


def _load_strata(path: Path, assignments: set[str]) -> dict[str, dict[str, Any]]:
    rows = load_jsonl(path)
    by_assignment: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(rows):
        name = f"agreement stratum[{index}]"
        row = expect_object(raw, name)
        expect_exact_fields(row, {"assignment_id", "severity", "slices"}, name)
        assignment_id = expect_identifier(row["assignment_id"], f"{name}.assignment_id")
        if assignment_id in by_assignment:
            raise ProtocolError("agreement strata contain duplicate assignment_id")
        expect_enum(
            row["severity"],
            {"low", "medium", "high", "critical"},
            f"{name}.severity",
        )
        if not isinstance(row["slices"], list) or not row["slices"]:
            raise ProtocolError(f"{name}.slices must be a non-empty array")
        slices = [
            expect_identifier(value, f"{name}.slices[]") for value in row["slices"]
        ]
        if len(set(slices)) != len(slices):
            raise ProtocolError(f"{name}.slices contains duplicates")
        by_assignment[assignment_id] = row
    if set(by_assignment) != assignments:
        raise ProtocolError("agreement strata assignment coverage mismatch")
    return by_assignment


def score_agreement(
    path: Path,
    *,
    packet: PacketContext,
    strata_path: Path | None = None,
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rows = load_jsonl(path)
    for raw in rows:
        assignment_id = raw.get("assignment_id") if isinstance(raw, dict) else None
        if assignment_id not in packet.cases_by_assignment:
            raise ProtocolError("agreement annotation is outside the bound packet")
        annotation = validate_annotation_for_case(
            raw,
            packet.cases_by_assignment[assignment_id],
            source_contents=packet.source_contents,
        )
        grouped[annotation["assignment_id"]].append(annotation)
    if not grouped:
        raise ProtocolError("agreement input is empty")
    if set(grouped) != set(packet.cases_by_assignment):
        raise ProtocolError("agreement annotations do not cover the bound packet")
    pairs_by_assignment: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for assignment_id, case_annotations in sorted(grouped.items()):
        if len(case_annotations) != 2:
            raise ProtocolError(
                f"agreement requires exactly two annotations for {assignment_id}"
            )
        if (
            case_annotations[0]["contributor_id"]
            == case_annotations[1]["contributor_id"]
        ):
            raise ProtocolError(
                f"agreement pair reuses contributor for {assignment_id}"
            )
        ordered = sorted(case_annotations, key=lambda value: value["contributor_id"])
        pairs_by_assignment[assignment_id] = (ordered[0], ordered[1])
    all_pairs = list(pairs_by_assignment.values())
    overall = _metric_bundle(all_pairs)

    strata = (
        _load_strata(strata_path, set(pairs_by_assignment))
        if strata_path is not None
        else None
    )
    high_critical_pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    by_language: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(
        list
    )
    by_profile: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(
        list
    )
    by_severity: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(
        list
    )
    by_slice: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for assignment_id, pair in pairs_by_assignment.items():
        case = packet.cases_by_assignment[assignment_id]
        by_language[case["language"]].append(pair)
        by_profile[case["profile"]].append(pair)
        if strata is not None:
            row = strata[assignment_id]
            severity = row["severity"]
            by_severity[severity].append(pair)
            if severity in {"high", "critical"}:
                high_critical_pairs.append(pair)
            for slice_name in row["slices"]:
                by_slice[slice_name].append(pair)

    high_critical_unsafe = _unsafe_metrics(high_critical_pairs)
    verdict_gate = (
        overall["verdict"]["status"] == "measured"
        and overall["verdict"]["kappa_basis_points"] >= 8_000
    )
    unsafe_gate = (
        high_critical_unsafe["status"] == "measured"
        and high_critical_unsafe["raw_agreement_basis_points"] >= 9_500
    )
    violation_gate = (
        overall["violations"]["status"] == "measured"
        and overall["violations"]["macro_f1_basis_points"] >= 8_000
    )
    gates = {
        "verdict_kappa_overall": verdict_gate,
        "unsafe_raw_agreement_high_critical": unsafe_gate,
        "violation_macro_f1_overall": violation_gate,
    }
    return {
        "assignment_count": len(all_pairs),
        "annotation_count": len(rows),
        "contributor_count": len({row["contributor_id"] for row in rows}),
        "overall": overall,
        "unsafe_high_critical": high_critical_unsafe,
        "strata_status": "measured" if strata is not None else "not_measured",
        "strata": {
            "language": {
                key: _metric_bundle(value) for key, value in sorted(by_language.items())
            },
            "profile": {
                key: _metric_bundle(value) for key, value in sorted(by_profile.items())
            },
            "severity": {
                key: _metric_bundle(value) for key, value in sorted(by_severity.items())
            },
            "slice": {
                key: _metric_bundle(value) for key, value in sorted(by_slice.items())
            },
        },
        "gates": gates,
        "all_gates_pass": all(gates.values()),
        "promotion_eligible": False,
    }
