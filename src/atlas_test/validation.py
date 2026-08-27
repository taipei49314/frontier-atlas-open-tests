"""Strict validators for public packet, annotation, and source records."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import (
    PROTOCOL_VERSION,
    ProtocolError,
    canonical_sha256,
    contained_path,
    expect_bool,
    expect_enum,
    expect_exact_fields,
    expect_identifier,
    expect_int,
    expect_object,
    expect_sha256,
    expect_text,
    expect_utc_timestamp,
    file_sha256,
    load_jsonl,
)


@dataclass(frozen=True)
class PacketContext:
    """Fully validated packet inputs used by linked protocol operations."""

    manifest: dict[str, Any]
    cases_by_assignment: dict[str, dict[str, Any]]
    sources_by_id: dict[str, dict[str, Any]]
    source_contents: dict[str, str]
    summary: dict[str, Any]


SEMANTIC_DIMENSIONS = (
    "subject",
    "predicate",
    "object",
    "scope",
    "quantity",
    "time",
    "condition",
    "modality",
    "attribution",
    "causality",
    "polarity",
)
DIMENSION_RELATIONS = {
    "aligned",
    "claim_weaker",
    "claim_stronger",
    "conflicts",
    "not_expressed",
    "ambiguous",
    "not_applicable",
}
CONFLICT_BASES = {
    "explicit_negation",
    "incompatible_value",
    "explicit_rejection",
    "explicit_incompatible_attribution",
    "explicit_incompatible_condition",
}
VERDICTS = {
    "entails",
    "partial_support",
    "contradicts",
    "insufficient_context",
    "ambiguous",
    "abstain",
}
VIOLATIONS = {
    "citation_mismatch",
    "source_credibility_unverified",
    "counterevidence_omitted",
    "semantic_shift",
    "attribution_error",
    "unsupported_inference",
    "direction_mismatch",
}
OVERALL_OUTCOMES = {"no_objection", "human_review", "unavailable"}
MAX_SOURCE_BYTES = 1024 * 1024


def _versioned(record: dict[str, Any], name: str) -> None:
    if expect_int(record["schema_version"], f"{name}.schema_version", minimum=1) != 1:
        raise ProtocolError(f"unsupported {name} schema_version")
    if record["protocol_version"] != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported {name} protocol_version")


def validate_case(record: Any) -> dict[str, Any]:
    case = expect_object(record, "case")
    fields = {
        "schema_version",
        "protocol_version",
        "assignment_id",
        "case_ref",
        "language",
        "profile",
        "claim",
        "source_text",
        "quoted_evidence",
        "quote_start",
        "quote_end",
        "context_before",
        "context_after",
        "source_snapshot_id",
        "source_span_id",
        "bounded_corpus_snapshot_ids",
    }
    expect_exact_fields(case, fields, "case")
    _versioned(case, "case")
    expect_identifier(case["assignment_id"], "case.assignment_id")
    expect_identifier(case["case_ref"], "case.case_ref")
    expect_enum(case["language"], {"en", "zh-Hant"}, "case.language")
    expect_enum(
        case["profile"],
        {"semantic_calibration", "real_source_calibration", "qualification"},
        "case.profile",
    )
    expect_text(case["claim"], "case.claim", maximum=10_000)
    source = expect_text(case["source_text"], "case.source_text", maximum=200_000)
    quote = expect_text(case["quoted_evidence"], "case.quoted_evidence", maximum=20_000)
    start = expect_int(case["quote_start"], "case.quote_start")
    end = expect_int(case["quote_end"], "case.quote_end")
    if end <= start or end > len(source):
        raise ProtocolError("case quote offsets are outside source_text")
    if source[start:end] != quote:
        raise ProtocolError("case quoted_evidence does not match source_text offsets")
    before = expect_text(
        case["context_before"], "case.context_before", allow_empty=True, maximum=20_000
    )
    after = expect_text(
        case["context_after"], "case.context_after", allow_empty=True, maximum=20_000
    )
    if before and not source[:start].endswith(before):
        raise ProtocolError("case context_before is not adjacent to quoted_evidence")
    if after and not source[end:].startswith(after):
        raise ProtocolError("case context_after is not adjacent to quoted_evidence")
    snapshot_id = case["source_snapshot_id"]
    if snapshot_id is not None:
        expect_identifier(snapshot_id, "case.source_snapshot_id")
    span_id = case["source_span_id"]
    if span_id is not None:
        expect_identifier(span_id, "case.source_span_id")
    if (snapshot_id is None) != (span_id is None):
        raise ProtocolError(
            "case source_snapshot_id and source_span_id must be set together"
        )
    corpus_ids = case["bounded_corpus_snapshot_ids"]
    if not isinstance(corpus_ids, list):
        raise ProtocolError("case.bounded_corpus_snapshot_ids must be an array")
    normalized_corpus_ids = [
        expect_identifier(value, "case.bounded_corpus_snapshot_ids[]")
        for value in corpus_ids
    ]
    if len(set(normalized_corpus_ids)) != len(normalized_corpus_ids):
        raise ProtocolError("case.bounded_corpus_snapshot_ids contains duplicates")
    if normalized_corpus_ids and snapshot_id is None:
        raise ProtocolError(
            "bounded corpus requires an immutable cited source snapshot"
        )
    if case["profile"] == "real_source_calibration" and snapshot_id is None:
        raise ProtocolError(
            "real_source_calibration requires source_snapshot_id and source_span_id"
        )
    return case


def load_packet_context(manifest: Any, *, base_dir: Path) -> PacketContext:
    packet = expect_object(manifest, "packet")
    fields = {
        "schema_version",
        "protocol_version",
        "packet_id",
        "created_at",
        "case_count",
        "cases_file",
        "cases_sha256",
        "source_count",
        "sources_file",
        "sources_sha256",
        "visibility",
        "authority",
    }
    expect_exact_fields(packet, fields, "packet")
    _versioned(packet, "packet")
    expect_identifier(packet["packet_id"], "packet.packet_id")
    expect_utc_timestamp(packet["created_at"], "packet.created_at")
    count = expect_int(packet["case_count"], "packet.case_count", minimum=1)
    cases_path = contained_path(base_dir, packet["cases_file"], "packet.cases_file")
    expected_hash = expect_sha256(packet["cases_sha256"], "packet.cases_sha256")
    if file_sha256(cases_path) != expected_hash:
        raise ProtocolError("packet cases_sha256 does not match cases_file")
    rows = load_jsonl(cases_path)
    if len(rows) != count:
        raise ProtocolError("packet case_count does not match cases_file")

    source_count = expect_int(packet["source_count"], "packet.source_count")
    sources_by_id: dict[str, dict[str, Any]] = {}
    source_contents: dict[str, str] = {}
    if source_count == 0:
        if packet["sources_file"] is not None or packet["sources_sha256"] is not None:
            raise ProtocolError(
                "zero-source packet must set sources_file and sources_sha256 to null"
            )
    else:
        sources_path = contained_path(
            base_dir, packet["sources_file"], "packet.sources_file"
        )
        sources_hash = expect_sha256(packet["sources_sha256"], "packet.sources_sha256")
        if file_sha256(sources_path) != sources_hash:
            raise ProtocolError("packet sources_sha256 does not match sources_file")
        source_rows = load_jsonl(sources_path)
        if len(source_rows) != source_count:
            raise ProtocolError("packet source_count does not match sources_file")
        for raw_source in source_rows:
            validated = validate_source_snapshot(raw_source, base_dir=base_dir)
            snapshot_id = validated["snapshot_id"]
            if snapshot_id in sources_by_id:
                raise ProtocolError("packet contains duplicate source snapshot_id")
            content_path = contained_path(
                base_dir,
                raw_source["content_file"],
                "source_snapshot.content_file",
            )
            try:
                source_content = content_path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise ProtocolError(
                    f"cannot read source snapshot content: {exc}", code="io_error"
                ) from exc
            sources_by_id[snapshot_id] = raw_source
            source_contents[snapshot_id] = source_content

    assignments: set[str] = set()
    refs: set[str] = set()
    cases_by_assignment: dict[str, dict[str, Any]] = {}
    referenced_sources: set[str] = set()
    for row in rows:
        case = validate_case(row)
        if case["assignment_id"] in assignments:
            raise ProtocolError("packet contains duplicate assignment_id")
        if case["case_ref"] in refs:
            raise ProtocolError("packet contains duplicate case_ref")
        assignments.add(case["assignment_id"])
        refs.add(case["case_ref"])
        cases_by_assignment[case["assignment_id"]] = case
        snapshot_id = case["source_snapshot_id"]
        if snapshot_id is not None:
            if snapshot_id not in sources_by_id:
                raise ProtocolError(
                    "case cites a source snapshot absent from the packet"
                )
            source_manifest = sources_by_id[snapshot_id]
            source_content = source_contents[snapshot_id]
            if case["source_text"] != source_content:
                raise ProtocolError(
                    "case source_text differs from immutable source snapshot"
                )
            span_id = case["source_span_id"]
            matching_spans = [
                span
                for span in source_manifest["exact_spans"]
                if span["span_id"] == span_id
            ]
            if len(matching_spans) != 1:
                raise ProtocolError(
                    "case source_span_id is absent from source snapshot"
                )
            source_span = matching_spans[0]
            if (
                source_span["start"] != case["quote_start"]
                or source_span["end"] != case["quote_end"]
            ):
                raise ProtocolError(
                    "case quote offsets differ from immutable source span"
                )
            referenced_sources.add(snapshot_id)
        for corpus_id in case["bounded_corpus_snapshot_ids"]:
            if corpus_id not in sources_by_id:
                raise ProtocolError(
                    "bounded corpus references a snapshot absent from the packet"
                )
            referenced_sources.add(corpus_id)
    if referenced_sources != set(sources_by_id):
        unused = sorted(set(sources_by_id) - referenced_sources)
        raise ProtocolError(f"packet contains unreferenced source snapshots: {unused}")
    visibility = expect_object(packet["visibility"], "packet.visibility")
    visibility_fields = {
        "labels_included",
        "model_outputs_included",
        "attack_metadata_included",
        "severity_included",
        "pair_ids_included",
        "assignment_map_private",
    }
    expect_exact_fields(visibility, visibility_fields, "packet.visibility")
    for field in visibility_fields:
        expect_bool(visibility[field], f"packet.visibility.{field}")
    forbidden_true = visibility_fields - {"assignment_map_private"}
    if any(visibility[field] for field in forbidden_true):
        raise ProtocolError("blind packet declares forbidden evaluator metadata")
    if visibility["assignment_map_private"] is not True:
        raise ProtocolError("blind packet assignment map must remain private")
    authority = expect_object(packet["authority"], "packet.authority")
    expect_exact_fields(
        authority,
        {"purpose", "promotion_eligible", "gold_authority", "blindness"},
        "packet.authority",
    )
    expect_enum(
        authority["purpose"],
        {"guideline_calibration", "qualification", "real_source_calibration"},
        "packet.authority.purpose",
    )
    if expect_bool(
        authority["promotion_eligible"], "packet.authority.promotion_eligible"
    ):
        raise ProtocolError("public packet cannot grant promotion authority")
    if expect_bool(authority["gold_authority"], "packet.authority.gold_authority"):
        raise ProtocolError("packet alone cannot grant gold authority")
    expect_enum(
        authority["blindness"],
        {"content_blinded_public_source", "strict_unpublished"},
        "packet.authority.blindness",
    )
    summary = {
        "packet_id": packet["packet_id"],
        "case_count": count,
        "cases_sha256": expected_hash,
        "source_count": source_count,
        "assignment_count": len(assignments),
        "source_bindings_verified": True,
        "promotion_eligible": False,
        "gold_authority": False,
    }
    return PacketContext(
        manifest=packet,
        cases_by_assignment=cases_by_assignment,
        sources_by_id=sources_by_id,
        source_contents=source_contents,
        summary=summary,
    )


def validate_packet(manifest: Any, *, base_dir: Path) -> dict[str, Any]:
    return load_packet_context(manifest, base_dir=base_dir).summary


def _validate_anchor(
    record: Any, name: str, *, allowed_fields: set[str]
) -> dict[str, Any]:
    anchor = expect_object(record, name)
    expect_exact_fields(anchor, {"field", "snippet", "occurrence"}, name)
    expect_enum(anchor["field"], allowed_fields, f"{name}.field")
    expect_text(anchor["snippet"], f"{name}.snippet", maximum=240)
    expect_int(anchor["occurrence"], f"{name}.occurrence", maximum=10_000)
    return anchor


def _validate_corpus_anchor(record: Any, name: str) -> dict[str, Any]:
    anchor = expect_object(record, name)
    expect_exact_fields(anchor, {"snapshot_id", "start", "end", "snippet"}, name)
    expect_identifier(anchor["snapshot_id"], f"{name}.snapshot_id")
    start = expect_int(anchor["start"], f"{name}.start")
    end = expect_int(anchor["end"], f"{name}.end")
    if end <= start:
        raise ProtocolError(f"{name}.end must be greater than start")
    expect_text(anchor["snippet"], f"{name}.snippet", maximum=20_000)
    return anchor


def validate_annotation(record: Any) -> dict[str, Any]:
    annotation = expect_object(record, "annotation")
    fields = {
        "schema_version",
        "protocol_version",
        "assignment_id",
        "case_sha256",
        "contributor_id",
        "completed_at",
        "citation_support",
        "source_assurance",
        "counterevidence",
        "overall",
        "notes",
    }
    expect_exact_fields(annotation, fields, "annotation")
    _versioned(annotation, "annotation")
    expect_identifier(annotation["assignment_id"], "annotation.assignment_id")
    expect_sha256(annotation["case_sha256"], "annotation.case_sha256")
    expect_identifier(annotation["contributor_id"], "annotation.contributor_id")
    expect_utc_timestamp(annotation["completed_at"], "annotation.completed_at")
    support = expect_object(
        annotation["citation_support"], "annotation.citation_support"
    )
    expect_exact_fields(
        support,
        {"verdict", "unsafe_to_clear", "violations", "assessments"},
        "annotation.citation_support",
    )
    verdict = expect_enum(support["verdict"], VERDICTS, "citation_support.verdict")
    unsafe = expect_bool(support["unsafe_to_clear"], "citation_support.unsafe_to_clear")
    if not isinstance(support["violations"], list):
        raise ProtocolError("citation_support.violations must be an array")
    violations = [
        expect_enum(value, VIOLATIONS, "citation_support.violations[]")
        for value in support["violations"]
    ]
    if len(set(violations)) != len(violations):
        raise ProtocolError("citation_support.violations contains duplicates")
    assessments = support["assessments"]
    if not isinstance(assessments, list) or len(assessments) != len(
        SEMANTIC_DIMENSIONS
    ):
        raise ProtocolError("citation_support.assessments must cover all 11 dimensions")
    seen: set[str] = set()
    for index, raw in enumerate(assessments):
        name = f"citation_support.assessments[{index}]"
        item = expect_object(raw, name)
        expect_exact_fields(
            item,
            {
                "dimension",
                "relation",
                "conflict_basis",
                "claim_anchors",
                "evidence_anchors",
            },
            name,
        )
        dimension = expect_enum(
            item["dimension"], set(SEMANTIC_DIMENSIONS), f"{name}.dimension"
        )
        if dimension in seen:
            raise ProtocolError(f"duplicate semantic dimension: {dimension}")
        seen.add(dimension)
        relation = expect_enum(
            item["relation"], DIMENSION_RELATIONS, f"{name}.relation"
        )
        basis = item["conflict_basis"]
        if relation == "conflicts":
            expect_enum(basis, CONFLICT_BASES, f"{name}.conflict_basis")
        elif basis is not None:
            raise ProtocolError(f"{name}.conflict_basis is only valid for conflicts")
        claim_anchors = item["claim_anchors"]
        evidence_anchors = item["evidence_anchors"]
        if not isinstance(claim_anchors, list) or not isinstance(
            evidence_anchors, list
        ):
            raise ProtocolError(f"{name} anchors must be arrays")
        for anchor_index, anchor in enumerate(claim_anchors):
            _validate_anchor(
                anchor,
                f"{name}.claim_anchors[{anchor_index}]",
                allowed_fields={"claim"},
            )
        for anchor_index, anchor in enumerate(evidence_anchors):
            _validate_anchor(
                anchor,
                f"{name}.evidence_anchors[{anchor_index}]",
                allowed_fields={"quoted_evidence", "context_before", "context_after"},
            )
        if relation == "not_applicable" and (claim_anchors or evidence_anchors):
            raise ProtocolError(f"{name} not_applicable must not carry anchors")
        if relation not in {"not_applicable"} and not claim_anchors:
            raise ProtocolError(f"{name} applicable relation requires a claim anchor")
        if (
            relation
            in {"aligned", "claim_weaker", "claim_stronger", "conflicts", "ambiguous"}
            and not evidence_anchors
        ):
            raise ProtocolError(f"{name} relation requires an evidence anchor")
    if seen != set(SEMANTIC_DIMENSIONS):
        raise ProtocolError("citation_support.assessments dimension coverage mismatch")
    if verdict != "entails" and not unsafe:
        raise ProtocolError("non-entailment verdict must be unsafe_to_clear")

    assurance = expect_object(
        annotation["source_assurance"], "annotation.source_assurance"
    )
    expect_exact_fields(
        assurance,
        {"provenance_status", "credibility_status", "corroboration_status"},
        "annotation.source_assurance",
    )
    provenance = expect_enum(
        assurance["provenance_status"],
        {"not_assessed", "verified", "unverified", "conflicting"},
        "source_assurance.provenance_status",
    )
    expect_enum(
        assurance["credibility_status"],
        {"not_assessed", "credible", "mixed", "weak", "unknown"},
        "source_assurance.credibility_status",
    )
    expect_enum(
        assurance["corroboration_status"],
        {"not_assessed", "corroborated", "uncorroborated", "conflicting"},
        "source_assurance.corroboration_status",
    )

    counter = expect_object(annotation["counterevidence"], "annotation.counterevidence")
    expect_exact_fields(
        counter,
        {
            "scope",
            "scan_status",
            "scanned_snapshot_ids",
            "conflicts_found",
            "conflict_anchors",
        },
        "annotation.counterevidence",
    )
    scope = expect_enum(
        counter["scope"],
        {"exact_citation_only", "bounded_corpus"},
        "counterevidence.scope",
    )
    scan = expect_enum(
        counter["scan_status"],
        {"not_requested", "complete", "partial", "unavailable"},
        "counterevidence.scan_status",
    )
    scanned_ids = counter["scanned_snapshot_ids"]
    if not isinstance(scanned_ids, list):
        raise ProtocolError("counterevidence.scanned_snapshot_ids must be an array")
    normalized_scanned_ids = [
        expect_identifier(value, "counterevidence.scanned_snapshot_ids[]")
        for value in scanned_ids
    ]
    if len(set(normalized_scanned_ids)) != len(normalized_scanned_ids):
        raise ProtocolError("counterevidence.scanned_snapshot_ids contains duplicates")
    conflicts = counter["conflicts_found"]
    if conflicts is not None:
        expect_bool(conflicts, "counterevidence.conflicts_found")
    anchors = counter["conflict_anchors"]
    if not isinstance(anchors, list):
        raise ProtocolError("counterevidence.conflict_anchors must be an array")
    for index, anchor in enumerate(anchors):
        normalized_anchor = _validate_corpus_anchor(
            anchor, f"counterevidence.conflict_anchors[{index}]"
        )
        if normalized_anchor["snapshot_id"] not in set(normalized_scanned_ids):
            raise ProtocolError(
                "counterevidence anchor must belong to a scanned snapshot"
            )
    if scope == "exact_citation_only":
        if (
            scan != "not_requested"
            or normalized_scanned_ids
            or conflicts is not None
            or anchors
        ):
            raise ProtocolError(
                "exact_citation_only counterevidence must remain explicitly not_requested"
            )
    elif scan == "not_requested" and (
        normalized_scanned_ids or conflicts is not None or anchors
    ):
        raise ProtocolError("not_requested counterevidence cannot claim a result")
    if scan == "complete" and not normalized_scanned_ids:
        raise ProtocolError("complete counterevidence scan requires scanned snapshots")
    if scan == "partial" and not normalized_scanned_ids:
        raise ProtocolError("partial counterevidence scan requires scanned snapshots")
    if scan in {"complete", "partial"} and conflicts is None:
        raise ProtocolError(
            "completed or partial counterevidence scan requires a boolean result"
        )
    if scan == "unavailable" and conflicts is not None:
        raise ProtocolError("unavailable counterevidence scan cannot claim a result")
    if conflicts is True and not anchors:
        raise ProtocolError("counterevidence conflict requires an exact anchor")
    if conflicts is False and anchors:
        raise ProtocolError(
            "counterevidence without conflicts cannot carry conflict anchors"
        )

    overall = expect_enum(annotation["overall"], OVERALL_OUTCOMES, "annotation.overall")
    expect_text(
        annotation["notes"], "annotation.notes", allow_empty=True, maximum=4_000
    )
    if overall == "no_objection" and unsafe:
        raise ProtocolError("unsafe annotation cannot have overall no_objection")
    if overall == "no_objection" and provenance in {"unverified", "conflicting"}:
        raise ProtocolError(
            "unverified/conflicting source cannot have overall no_objection"
        )
    if (
        overall == "no_objection"
        and scope == "bounded_corpus"
        and (scan != "complete" or conflicts is not False)
    ):
        raise ProtocolError(
            "bounded-corpus no_objection requires a complete scan with no conflicts"
        )
    return annotation


def _require_anchor_occurrence(
    anchor: dict[str, Any], case: dict[str, Any], name: str
) -> None:
    field = anchor["field"]
    text = case[field]
    snippet = anchor["snippet"]
    cursor = 0
    observed = -1
    for _ in range(anchor["occurrence"] + 1):
        observed = text.find(snippet, cursor)
        if observed < 0:
            raise ProtocolError(f"{name} does not occur in bound case field {field}")
        cursor = observed + 1


def validate_annotation_for_case(
    record: Any,
    case_record: Any,
    *,
    source_contents: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Validate an annotation against exact case bytes and optional corpus bytes."""

    annotation = validate_annotation(record)
    case = validate_case(case_record)
    if annotation["assignment_id"] != case["assignment_id"]:
        raise ProtocolError("annotation assignment_id differs from bound case")
    observed_case_hash = canonical_sha256(case)
    if annotation["case_sha256"] != observed_case_hash:
        raise ProtocolError("annotation case_sha256 differs from bound case")
    for assessment_index, assessment in enumerate(
        annotation["citation_support"]["assessments"]
    ):
        for anchor_index, anchor in enumerate(assessment["claim_anchors"]):
            _require_anchor_occurrence(
                anchor,
                case,
                f"assessment[{assessment_index}].claim_anchors[{anchor_index}]",
            )
        for anchor_index, anchor in enumerate(assessment["evidence_anchors"]):
            _require_anchor_occurrence(
                anchor,
                case,
                f"assessment[{assessment_index}].evidence_anchors[{anchor_index}]",
            )

    counter = annotation["counterevidence"]
    if counter["scope"] == "bounded_corpus":
        available_ids = set(case["bounded_corpus_snapshot_ids"])
        if not available_ids:
            raise ProtocolError(
                "bounded-corpus annotation has no corpus in the bound case"
            )
        scanned_ids = set(counter["scanned_snapshot_ids"])
        if not scanned_ids.issubset(available_ids):
            raise ProtocolError(
                "annotation scanned snapshots outside the bounded corpus"
            )
        if counter["scan_status"] == "complete" and scanned_ids != available_ids:
            raise ProtocolError("complete scan must cover the entire bounded corpus")
        if counter["scan_status"] == "partial" and scanned_ids == available_ids:
            raise ProtocolError("partial scan cannot claim the entire bounded corpus")
        corpus = source_contents or {}
        for index, anchor in enumerate(counter["conflict_anchors"]):
            snapshot_id = anchor["snapshot_id"]
            if snapshot_id not in corpus:
                raise ProtocolError(
                    f"counterevidence anchor[{index}] source content is unavailable"
                )
            content = corpus[snapshot_id]
            start = anchor["start"]
            end = anchor["end"]
            if end > len(content) or content[start:end] != anchor["snippet"]:
                raise ProtocolError(
                    f"counterevidence anchor[{index}] differs from source snapshot bytes"
                )
    return annotation


def validate_source_snapshot(manifest: Any, *, base_dir: Path) -> dict[str, Any]:
    source = expect_object(manifest, "source_snapshot")
    fields = {
        "schema_version",
        "protocol_version",
        "snapshot_id",
        "source_type",
        "uri",
        "title",
        "author",
        "organization",
        "published_at",
        "acquired_at",
        "license_status",
        "license_reference",
        "content_encoding",
        "content_file",
        "content_sha256",
        "normalizer_version",
        "exact_spans",
    }
    expect_exact_fields(source, fields, "source_snapshot")
    _versioned(source, "source_snapshot")
    expect_identifier(source["snapshot_id"], "source_snapshot.snapshot_id")
    expect_enum(
        source["source_type"],
        {
            "official_technical_documentation",
            "government_notice",
            "public_filing",
            "peer_reviewed_abstract",
        },
        "source_snapshot.source_type",
    )
    for field in ("uri", "title"):
        expect_text(source[field], f"source_snapshot.{field}", maximum=4_000)
    for field in ("author", "organization", "published_at", "license_reference"):
        value = source[field]
        if value is not None:
            expect_text(value, f"source_snapshot.{field}", maximum=4_000)
    expect_utc_timestamp(source["acquired_at"], "source_snapshot.acquired_at")
    expect_enum(
        source["license_status"],
        {"permission", "public_domain", "licensed", "unknown", "restricted"},
        "source_snapshot.license_status",
    )
    if source["content_encoding"] != "utf-8":
        raise ProtocolError("source_snapshot.content_encoding must be utf-8")
    content_path = contained_path(
        base_dir, source["content_file"], "source_snapshot.content_file"
    )
    try:
        if content_path.stat().st_size > MAX_SOURCE_BYTES:
            raise ProtocolError(f"source snapshot exceeds {MAX_SOURCE_BYTES} bytes")
    except OSError as exc:
        raise ProtocolError(
            f"cannot inspect source snapshot content: {exc}", code="io_error"
        ) from exc
    expected_hash = expect_sha256(
        source["content_sha256"], "source_snapshot.content_sha256"
    )
    if file_sha256(content_path) != expected_hash:
        raise ProtocolError("source snapshot content hash mismatch")
    try:
        content = content_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ProtocolError(
            f"cannot read source snapshot content: {exc}", code="io_error"
        ) from exc
    expect_identifier(
        source["normalizer_version"], "source_snapshot.normalizer_version"
    )
    spans = source["exact_spans"]
    if not isinstance(spans, list) or not spans:
        raise ProtocolError("source_snapshot.exact_spans must be a non-empty array")
    seen: set[str] = set()
    for index, raw in enumerate(spans):
        name = f"source_snapshot.exact_spans[{index}]"
        span = expect_object(raw, name)
        expect_exact_fields(span, {"span_id", "start", "end", "text_sha256"}, name)
        span_id = expect_identifier(span["span_id"], f"{name}.span_id")
        if span_id in seen:
            raise ProtocolError("duplicate source snapshot span_id")
        seen.add(span_id)
        start = expect_int(span["start"], f"{name}.start")
        end = expect_int(span["end"], f"{name}.end")
        if end <= start or end > len(content):
            raise ProtocolError(f"{name} offsets are outside content")
        observed = hashlib.sha256(content[start:end].encode("utf-8")).hexdigest()
        if observed != expect_sha256(span["text_sha256"], f"{name}.text_sha256"):
            raise ProtocolError(f"{name} text hash mismatch")
    return {
        "snapshot_id": source["snapshot_id"],
        "content_sha256": expected_hash,
        "span_count": len(spans),
        "license_status": source["license_status"],
    }
