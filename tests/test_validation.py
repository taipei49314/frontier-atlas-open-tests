from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from atlas_test.canonical import (
    PROTOCOL_VERSION,
    ProtocolError,
    file_sha256,
)
from atlas_test.validation import (
    load_packet_context,
    validate_annotation,
    validate_annotation_for_case,
    validate_case,
    validate_packet,
    validate_source_snapshot,
)
from tests.helpers import (
    make_annotation,
    make_case,
    make_packet_manifest,
    sha256_bytes,
    write_jsonl,
)


class ValidationTests(unittest.TestCase):
    def test_case_requires_exact_quote_offsets(self) -> None:
        case = make_case()
        validate_case(case)
        case["quote_start"] += 1
        with self.assertRaisesRegex(ProtocolError, "quoted_evidence"):
            validate_case(case)

    def test_case_rejects_hidden_evaluator_metadata(self) -> None:
        case = make_case()
        case["severity"] = "critical"
        with self.assertRaisesRegex(ProtocolError, "extra=.*severity"):
            validate_case(case)

    def test_packet_validates_hash_blindness_and_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = make_packet_manifest(root, [make_case()])
            result = validate_packet(manifest, base_dir=root)
            self.assertEqual(result["case_count"], 1)
            escaped = copy.deepcopy(manifest)
            escaped["cases_file"] = "../cases.jsonl"
            with self.assertRaisesRegex(ProtocolError, "stay within"):
                validate_packet(escaped, base_dir=root)
            promoted = copy.deepcopy(manifest)
            promoted["authority"]["promotion_eligible"] = True
            with self.assertRaisesRegex(ProtocolError, "promotion"):
                validate_packet(promoted, base_dir=root)

    def test_annotation_requires_all_dimensions_and_fail_closed(self) -> None:
        annotation = make_annotation()
        validate_annotation(annotation)
        missing = copy.deepcopy(annotation)
        missing["citation_support"]["assessments"].pop()
        with self.assertRaisesRegex(ProtocolError, "all 11"):
            validate_annotation(missing)
        unsafe_clear = make_annotation(unsafe=True)
        unsafe_clear["citation_support"]["unsafe_to_clear"] = False
        with self.assertRaisesRegex(ProtocolError, "non-entailment"):
            validate_annotation(unsafe_clear)

    def test_annotation_is_bound_to_case_hash_and_real_anchors(self) -> None:
        case = make_case()
        annotation = make_annotation(case=case)
        validate_annotation_for_case(annotation, case)
        wrong_hash = copy.deepcopy(annotation)
        wrong_hash["case_sha256"] = "0" * 64
        with self.assertRaisesRegex(ProtocolError, "case_sha256"):
            validate_annotation_for_case(wrong_hash, case)
        fake_anchor = copy.deepcopy(annotation)
        fake_anchor["citation_support"]["assessments"][0]["claim_anchors"][0][
            "snippet"
        ] = "not present"
        with self.assertRaisesRegex(ProtocolError, "does not occur"):
            validate_annotation_for_case(fake_anchor, case)

    def test_unverified_source_cannot_be_no_objection(self) -> None:
        annotation = make_annotation()
        annotation["source_assurance"]["provenance_status"] = "unverified"
        with self.assertRaisesRegex(ProtocolError, "unverified"):
            validate_annotation(annotation)

    def test_source_snapshot_binds_bytes_and_spans(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = "Version 1 states that the limit is ten."
            content_path = root / "source.txt"
            content_path.write_text(content, encoding="utf-8", newline="\n")
            snippet = "the limit is ten"
            start = content.index(snippet)
            manifest = {
                "schema_version": 1,
                "protocol_version": PROTOCOL_VERSION,
                "snapshot_id": "snapshot-001",
                "source_type": "official_technical_documentation",
                "uri": "https://example.invalid/docs/v1",
                "title": "Example documentation",
                "author": None,
                "organization": "Example",
                "published_at": "2026-08-01",
                "acquired_at": "2026-08-27T08:00:00Z",
                "license_status": "permission",
                "license_reference": "fixture permission",
                "content_encoding": "utf-8",
                "content_file": "source.txt",
                "content_sha256": file_sha256(content_path),
                "normalizer_version": "exact-text-v1",
                "exact_spans": [
                    {
                        "span_id": "span-001",
                        "start": start,
                        "end": start + len(snippet),
                        "text_sha256": sha256_bytes(snippet.encode("utf-8")),
                    }
                ],
            }
            result = validate_source_snapshot(manifest, base_dir=root)
            self.assertEqual(result["span_count"], 1)
            content_path.write_text(content + " changed", encoding="utf-8")
            with self.assertRaisesRegex(ProtocolError, "content hash"):
                validate_source_snapshot(manifest, base_dir=root)

    def test_packet_binds_real_source_and_bounded_corpus_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = "Before Sales doubled. After"
            content_path = root / "source.txt"
            content_path.write_text(content, encoding="utf-8", newline="\n")
            quote = "Sales doubled."
            start = content.index(quote)
            snapshot = {
                "schema_version": 1,
                "protocol_version": PROTOCOL_VERSION,
                "snapshot_id": "snapshot-001",
                "source_type": "official_technical_documentation",
                "uri": "https://example.invalid/docs/v1",
                "title": "Example documentation",
                "author": None,
                "organization": "Example",
                "published_at": "2026-08-01",
                "acquired_at": "2026-08-27T08:00:00Z",
                "license_status": "permission",
                "license_reference": "fixture permission",
                "content_encoding": "utf-8",
                "content_file": "source.txt",
                "content_sha256": file_sha256(content_path),
                "normalizer_version": "exact-text-v1",
                "exact_spans": [
                    {
                        "span_id": "span-001",
                        "start": start,
                        "end": start + len(quote),
                        "text_sha256": sha256_bytes(quote.encode("utf-8")),
                    }
                ],
            }
            sources_path = root / "sources.jsonl"
            write_jsonl(sources_path, [snapshot])
            case = make_case()
            case.update(
                {
                    "profile": "real_source_calibration",
                    "source_snapshot_id": "snapshot-001",
                    "source_span_id": "span-001",
                    "bounded_corpus_snapshot_ids": ["snapshot-001"],
                }
            )
            packet = make_packet_manifest(
                root, [case], purpose="real_source_calibration"
            )
            packet.update(
                {
                    "source_count": 1,
                    "sources_file": "sources.jsonl",
                    "sources_sha256": file_sha256(sources_path),
                }
            )
            context = load_packet_context(packet, base_dir=root)
            annotation = make_annotation(case=case)
            annotation["counterevidence"] = {
                "scope": "bounded_corpus",
                "scan_status": "complete",
                "scanned_snapshot_ids": ["snapshot-001"],
                "conflicts_found": False,
                "conflict_anchors": [],
            }
            validate_annotation_for_case(
                annotation, case, source_contents=context.source_contents
            )
            incomplete = copy.deepcopy(annotation)
            incomplete["counterevidence"]["scan_status"] = "partial"
            incomplete["overall"] = "human_review"
            with self.assertRaisesRegex(ProtocolError, "partial scan"):
                validate_annotation_for_case(
                    incomplete, case, source_contents=context.source_contents
                )
            changed_case = copy.deepcopy(case)
            changed_case["source_text"] += " "
            changed_case["context_after"] += " "
            changed_packet = make_packet_manifest(
                root, [changed_case], purpose="real_source_calibration"
            )
            changed_packet.update(
                {
                    "source_count": 1,
                    "sources_file": "sources.jsonl",
                    "sources_sha256": file_sha256(sources_path),
                }
            )
            with self.assertRaisesRegex(ProtocolError, "immutable source snapshot"):
                load_packet_context(changed_packet, base_dir=root)


if __name__ == "__main__":
    unittest.main()
