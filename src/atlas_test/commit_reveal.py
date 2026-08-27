"""Domain-separated annotation commitment and reveal records."""

from __future__ import annotations

import os
import re
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any

from .canonical import (
    CANONICALIZATION_VERSION,
    PROTOCOL_VERSION,
    ProtocolError,
    canonical_sha256,
    expect_exact_fields,
    expect_identifier,
    expect_int,
    expect_object,
    expect_sha256,
    expect_text,
    expect_utc_timestamp,
)
from .validation import validate_annotation

COMMITMENT_DOMAIN = "frontier-atlas-annotation-commit-v1"
_SALT_RE = re.compile(r"^[A-Za-z0-9_-]{32,256}$")


def read_salt(path: Path) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise ProtocolError(
            f"cannot read salt file {path}: {exc}", code="io_error"
        ) from exc
    if _SALT_RE.fullmatch(value) is None:
        raise ProtocolError("salt must be 32-256 URL-safe random characters")
    return value


def generate_salt(path: Path) -> dict[str, Any]:
    value = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise ProtocolError(
            f"refusing to overwrite salt file {path}: {exc}", code="io_error"
        ) from exc
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(value + "\n")
    return {"path": str(path), "salt_chars": len(value), "overwritten": False}


def commitment_digest(annotation: dict[str, Any], salt: str) -> str:
    validate_annotation(annotation)
    if _SALT_RE.fullmatch(salt) is None:
        raise ProtocolError("salt must be 32-256 URL-safe random characters")
    preimage = {
        "annotation": annotation,
        "assignment_id": annotation["assignment_id"],
        "contributor_id": annotation["contributor_id"],
        "domain": COMMITMENT_DOMAIN,
        "salt": salt,
    }
    return canonical_sha256(preimage)


def create_commitment(
    annotation: dict[str, Any], salt: str, *, committed_at: str
) -> dict[str, Any]:
    validate_annotation(annotation)
    expect_utc_timestamp(committed_at, "committed_at")
    completed = _timestamp(annotation["completed_at"])
    committed = _timestamp(committed_at)
    if committed < completed:
        raise ProtocolError("commitment cannot predate annotation completion")
    digest = commitment_digest(annotation, salt)
    return {
        "schema_version": 1,
        "protocol_version": PROTOCOL_VERSION,
        "canonicalization_version": CANONICALIZATION_VERSION,
        "commitment_id": f"commit-{digest[:24]}",
        "assignment_id": annotation["assignment_id"],
        "contributor_id": annotation["contributor_id"],
        "committed_at": committed_at,
        "commitment_sha256": digest,
    }


def validate_commitment(record: Any) -> dict[str, Any]:
    value = expect_object(record, "commitment")
    expect_exact_fields(
        value,
        {
            "schema_version",
            "protocol_version",
            "canonicalization_version",
            "commitment_id",
            "assignment_id",
            "contributor_id",
            "committed_at",
            "commitment_sha256",
        },
        "commitment",
    )
    if expect_int(value["schema_version"], "commitment.schema_version", minimum=1) != 1:
        raise ProtocolError("unsupported commitment schema_version")
    if value["protocol_version"] != PROTOCOL_VERSION:
        raise ProtocolError("unsupported commitment protocol_version")
    if value["canonicalization_version"] != CANONICALIZATION_VERSION:
        raise ProtocolError("unsupported commitment canonicalization_version")
    expect_identifier(value["commitment_id"], "commitment.commitment_id")
    expect_identifier(value["assignment_id"], "commitment.assignment_id")
    expect_identifier(value["contributor_id"], "commitment.contributor_id")
    expect_utc_timestamp(value["committed_at"], "commitment.committed_at")
    digest = expect_sha256(value["commitment_sha256"], "commitment.commitment_sha256")
    if value["commitment_id"] != f"commit-{digest[:24]}":
        raise ProtocolError("commitment_id does not match commitment digest")
    return value


def create_reveal(
    commitment: dict[str, Any],
    annotation: dict[str, Any],
    salt: str,
    *,
    revealed_at: str,
) -> dict[str, Any]:
    validate_commitment(commitment)
    validate_annotation(annotation)
    expect_utc_timestamp(revealed_at, "revealed_at")
    if annotation["assignment_id"] != commitment["assignment_id"]:
        raise ProtocolError("reveal assignment_id differs from commitment")
    if annotation["contributor_id"] != commitment["contributor_id"]:
        raise ProtocolError("reveal contributor_id differs from commitment")
    if _timestamp(revealed_at) < _timestamp(commitment["committed_at"]):
        raise ProtocolError("reveal cannot predate commitment")
    if commitment_digest(annotation, salt) != commitment["commitment_sha256"]:
        raise ProtocolError("annotation or salt does not match commitment")
    return {
        "schema_version": 1,
        "protocol_version": PROTOCOL_VERSION,
        "canonicalization_version": CANONICALIZATION_VERSION,
        "commitment_id": commitment["commitment_id"],
        "commitment_record_sha256": canonical_sha256(commitment),
        "assignment_id": annotation["assignment_id"],
        "contributor_id": annotation["contributor_id"],
        "revealed_at": revealed_at,
        "salt": salt,
        "annotation": annotation,
    }


def verify_reveal(commitment: Any, reveal: Any) -> dict[str, Any]:
    committed = validate_commitment(commitment)
    value = expect_object(reveal, "reveal")
    expect_exact_fields(
        value,
        {
            "schema_version",
            "protocol_version",
            "canonicalization_version",
            "commitment_id",
            "commitment_record_sha256",
            "assignment_id",
            "contributor_id",
            "revealed_at",
            "salt",
            "annotation",
        },
        "reveal",
    )
    if expect_int(value["schema_version"], "reveal.schema_version", minimum=1) != 1:
        raise ProtocolError("unsupported reveal schema_version")
    if value["protocol_version"] != PROTOCOL_VERSION:
        raise ProtocolError("unsupported reveal protocol_version")
    if value["canonicalization_version"] != CANONICALIZATION_VERSION:
        raise ProtocolError("unsupported reveal canonicalization_version")
    if (
        expect_identifier(value["commitment_id"], "reveal.commitment_id")
        != committed["commitment_id"]
    ):
        raise ProtocolError("reveal commitment_id mismatch")
    expected_record_hash = canonical_sha256(committed)
    if (
        expect_sha256(
            value["commitment_record_sha256"], "reveal.commitment_record_sha256"
        )
        != expected_record_hash
    ):
        raise ProtocolError("reveal does not bind the supplied commitment record")
    annotation = validate_annotation(value["annotation"])
    if (
        value["assignment_id"] != committed["assignment_id"]
        or value["assignment_id"] != annotation["assignment_id"]
    ):
        raise ProtocolError("reveal assignment identity mismatch")
    if (
        value["contributor_id"] != committed["contributor_id"]
        or value["contributor_id"] != annotation["contributor_id"]
    ):
        raise ProtocolError("reveal contributor identity mismatch")
    expect_utc_timestamp(value["revealed_at"], "reveal.revealed_at")
    if _timestamp(value["revealed_at"]) < _timestamp(committed["committed_at"]):
        raise ProtocolError("reveal predates commitment")
    salt = expect_text(value["salt"], "reveal.salt", maximum=256)
    observed = commitment_digest(annotation, salt)
    if observed != committed["commitment_sha256"]:
        raise ProtocolError("reveal digest does not match commitment")
    return {
        "valid": True,
        "commitment_id": committed["commitment_id"],
        "assignment_id": committed["assignment_id"],
        "contributor_id": committed["contributor_id"],
        "commitment_sha256": observed,
        "annotation_sha256": canonical_sha256(annotation),
    }


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value)
