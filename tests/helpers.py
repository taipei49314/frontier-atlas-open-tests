from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from atlas_test.canonical import PROTOCOL_VERSION, canonical_sha256, file_sha256
from atlas_test.validation import (
    SEMANTIC_DIMENSIONS,
    PacketContext,
    load_packet_context,
)

CLAIM = "Sales doubled."
SOURCE = "Before Sales doubled. After"
QUOTE = "Sales doubled."


def anchor(field: str, snippet: str) -> dict[str, Any]:
    return {"field": field, "snippet": snippet, "occurrence": 0}


def make_annotation(
    *,
    assignment_id: str = "assign-001",
    contributor_id: str = "contributor-a",
    unsafe: bool = False,
    completed_at: str = "2026-08-27T08:00:00Z",
    case: dict[str, Any] | None = None,
) -> dict[str, Any]:
    bound_case = case or make_case(assignment_id=assignment_id)
    assessments = []
    for dimension in SEMANTIC_DIMENSIONS:
        relation = "claim_stronger" if unsafe and dimension == "scope" else "aligned"
        assessments.append(
            {
                "dimension": dimension,
                "relation": relation,
                "conflict_basis": None,
                "claim_anchors": [anchor("claim", CLAIM)],
                "evidence_anchors": [anchor("quoted_evidence", QUOTE)],
            }
        )
    return {
        "schema_version": 1,
        "protocol_version": PROTOCOL_VERSION,
        "assignment_id": assignment_id,
        "case_sha256": canonical_sha256(bound_case),
        "contributor_id": contributor_id,
        "completed_at": completed_at,
        "citation_support": {
            "verdict": "partial_support" if unsafe else "entails",
            "unsafe_to_clear": unsafe,
            "violations": ["semantic_shift"] if unsafe else [],
            "assessments": assessments,
        },
        "source_assurance": {
            "provenance_status": "not_assessed",
            "credibility_status": "not_assessed",
            "corroboration_status": "not_assessed",
        },
        "counterevidence": {
            "scope": "exact_citation_only",
            "scan_status": "not_requested",
            "scanned_snapshot_ids": [],
            "conflicts_found": None,
            "conflict_anchors": [],
        },
        "overall": "human_review" if unsafe else "no_objection",
        "notes": "",
    }


def make_case(
    *, assignment_id: str = "assign-001", case_ref: str = "blind-001"
) -> dict[str, Any]:
    start = SOURCE.index(QUOTE)
    return {
        "schema_version": 1,
        "protocol_version": PROTOCOL_VERSION,
        "assignment_id": assignment_id,
        "case_ref": case_ref,
        "language": "en",
        "profile": "semantic_calibration",
        "claim": CLAIM,
        "source_text": SOURCE,
        "quoted_evidence": QUOTE,
        "quote_start": start,
        "quote_end": start + len(QUOTE),
        "context_before": "Before ",
        "context_after": " After",
        "source_snapshot_id": None,
        "source_span_id": None,
        "bounded_corpus_snapshot_ids": [],
    }


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows
        ),
        encoding="utf-8",
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def make_packet_manifest(
    root: Path,
    cases: list[dict[str, Any]],
    *,
    packet_id: str = "packet-001",
    purpose: str = "guideline_calibration",
) -> dict[str, Any]:
    cases_path = root / "cases.jsonl"
    write_jsonl(cases_path, cases)
    return {
        "schema_version": 1,
        "protocol_version": PROTOCOL_VERSION,
        "packet_id": packet_id,
        "created_at": "2026-08-27T08:00:00Z",
        "case_count": len(cases),
        "cases_file": "cases.jsonl",
        "cases_sha256": file_sha256(cases_path),
        "source_count": 0,
        "sources_file": None,
        "sources_sha256": None,
        "visibility": {
            "labels_included": False,
            "model_outputs_included": False,
            "attack_metadata_included": False,
            "severity_included": False,
            "pair_ids_included": False,
            "assignment_map_private": True,
        },
        "authority": {
            "purpose": purpose,
            "promotion_eligible": False,
            "gold_authority": False,
            "blindness": "content_blinded_public_source",
        },
    }


def write_packet(
    root: Path,
    cases: list[dict[str, Any]],
    *,
    packet_id: str = "packet-001",
    purpose: str = "guideline_calibration",
) -> tuple[Path, PacketContext]:
    manifest = make_packet_manifest(root, cases, packet_id=packet_id, purpose=purpose)
    manifest_path = root / "packet.json"
    write_json(manifest_path, manifest)
    return manifest_path, load_packet_context(manifest, base_dir=root)
