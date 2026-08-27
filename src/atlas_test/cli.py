"""Command-line interface for the offline public-test protocol."""

from __future__ import annotations

import argparse
import json
import sys
from importlib import resources
from pathlib import Path
from typing import Any

from . import __version__
from .agreement import score_agreement
from .canonical import (
    CANONICALIZATION_VERSION,
    PROTOCOL_VERSION,
    ProtocolError,
    canonical_bytes,
    canonical_sha256,
    load_json,
    write_bytes_atomic,
    write_json,
)
from .commit_reveal import (
    create_commitment,
    create_reveal,
    generate_salt,
    read_salt,
    validate_commitment,
    verify_reveal,
)
from .identity import verify_git_identity
from .qualification import score_qualification
from .validation import (
    PacketContext,
    load_packet_context,
    validate_annotation_for_case,
    validate_source_snapshot,
)

EXPECTED_SCHEMAS = {
    "agreement-strata.schema.json",
    "annotation.schema.json",
    "case.schema.json",
    "commitment.schema.json",
    "packet.schema.json",
    "qualification-key.schema.json",
    "reveal.schema.json",
    "source-snapshot.schema.json",
}


class ProtocolArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ProtocolError(message, code="usage_error")


def build_parser() -> argparse.ArgumentParser:
    parser = ProtocolArgumentParser(
        prog="atlas-test",
        description="Offline Frontier Atlas packet, annotation, and commit-reveal verifier.",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit one stable JSON object to stdout"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("doctor", help="verify offline runtime and schema availability")

    schemas = commands.add_parser(
        "schemas", help="discover bundled public JSON schemas"
    )
    schemas_sub = schemas.add_subparsers(dest="schemas_command", required=True)
    schemas_sub.add_parser("list", help="list schema names and SHA-256 digests")

    canonical = commands.add_parser(
        "canonicalize", help="canonicalize and hash a JSON value"
    )
    canonical.add_argument("--input", required=True, type=Path)
    canonical.add_argument(
        "--out", type=Path, help="optional compact canonical JSON output"
    )

    packet = commands.add_parser("packet", help="validate blind public packets")
    packet_sub = packet.add_subparsers(dest="packet_command", required=True)
    packet_validate = packet_sub.add_parser(
        "validate", help="validate packet manifest and cases"
    )
    packet_validate.add_argument("--packet", required=True, type=Path)

    annotation = commands.add_parser("annotation", help="validate one human annotation")
    annotation_sub = annotation.add_subparsers(dest="annotation_command", required=True)
    annotation_validate = annotation_sub.add_parser(
        "validate", help="validate strict annotation JSON"
    )
    annotation_validate.add_argument("--annotation", required=True, type=Path)
    annotation_validate.add_argument("--packet", required=True, type=Path)

    source = commands.add_parser("source", help="validate immutable source snapshots")
    source_sub = source.add_subparsers(dest="source_command", required=True)
    source_validate = source_sub.add_parser(
        "validate", help="validate source manifest, bytes, and spans"
    )
    source_validate.add_argument("--manifest", required=True, type=Path)

    salt = commands.add_parser("salt", help="manage local reveal salt")
    salt_sub = salt.add_subparsers(dest="salt_command", required=True)
    salt_generate = salt_sub.add_parser(
        "generate", help="create a new non-overwriting random salt file"
    )
    salt_generate.add_argument("--out", required=True, type=Path)

    commitment = commands.add_parser(
        "commitment", help="create or validate blinded commitments"
    )
    commitment_sub = commitment.add_subparsers(dest="commitment_command", required=True)
    commitment_create = commitment_sub.add_parser(
        "create", help="create commitment without disclosing annotation"
    )
    commitment_create.add_argument("--annotation", required=True, type=Path)
    commitment_create.add_argument("--packet", required=True, type=Path)
    commitment_create.add_argument("--salt-file", required=True, type=Path)
    commitment_create.add_argument("--committed-at", required=True)
    commitment_create.add_argument("--out", required=True, type=Path)
    commitment_validate = commitment_sub.add_parser(
        "validate", help="validate commitment record shape"
    )
    commitment_validate.add_argument("--commitment", required=True, type=Path)

    reveal = commands.add_parser("reveal", help="create or verify annotation reveals")
    reveal_sub = reveal.add_subparsers(dest="reveal_command", required=True)
    reveal_create = reveal_sub.add_parser(
        "create", help="create reveal bound to a prior commitment"
    )
    reveal_create.add_argument("--commitment", required=True, type=Path)
    reveal_create.add_argument("--annotation", required=True, type=Path)
    reveal_create.add_argument("--packet", required=True, type=Path)
    reveal_create.add_argument("--salt-file", required=True, type=Path)
    reveal_create.add_argument("--revealed-at", required=True)
    reveal_create.add_argument("--out", required=True, type=Path)
    reveal_verify = reveal_sub.add_parser(
        "verify", help="recompute and verify a reveal"
    )
    reveal_verify.add_argument("--commitment", required=True, type=Path)
    reveal_verify.add_argument("--reveal", required=True, type=Path)
    reveal_verify.add_argument("--packet", required=True, type=Path)

    identity = commands.add_parser("identity", help="verify signed Git provenance")
    identity_sub = identity.add_subparsers(dest="identity_command", required=True)
    identity_verify = identity_sub.add_parser(
        "verify-git", help="verify a signed Git commit offline"
    )
    identity_verify.add_argument("--repo", required=True, type=Path)
    identity_verify.add_argument("--commit", required=True)
    identity_verify.add_argument("--out", type=Path)

    qualification = commands.add_parser(
        "qualification", help="score a hidden qualification locally"
    )
    qualification_sub = qualification.add_subparsers(
        dest="qualification_command", required=True
    )
    qualification_score = qualification_sub.add_parser(
        "score", help="score submission without exposing answers"
    )
    qualification_score.add_argument("--key", required=True, type=Path)
    qualification_score.add_argument("--submission", required=True, type=Path)
    qualification_score.add_argument("--packet", required=True, type=Path)
    qualification_score.add_argument("--out", type=Path)

    agreement = commands.add_parser(
        "agreement", help="measure dual-annotation agreement"
    )
    agreement_sub = agreement.add_subparsers(dest="agreement_command", required=True)
    agreement_score = agreement_sub.add_parser(
        "score", help="compute preregistered overall IAA metrics"
    )
    agreement_score.add_argument("--annotations", required=True, type=Path)
    agreement_score.add_argument("--packet", required=True, type=Path)
    agreement_score.add_argument(
        "--strata",
        type=Path,
        help="private assignment severity/slice JSONL; required for high/critical gate",
    )
    agreement_score.add_argument("--out", type=Path)
    return parser


def _schema_records() -> list[dict[str, Any]]:
    root = resources.files("atlas_test").joinpath("schemas")
    records = []
    for item in sorted(root.iterdir(), key=lambda value: value.name):
        if item.name.endswith(".json"):
            payload = item.read_bytes()
            try:
                json.loads(payload)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise ProtocolError(
                    f"bundled schema {item.name} is invalid JSON: {exc}",
                    code="installation_error",
                ) from exc
            import hashlib

            records.append(
                {
                    "name": item.name,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "bytes": len(payload),
                }
            )
    return records


def _packet_context(path: Path) -> PacketContext:
    return load_packet_context(load_json(path), base_dir=path.parent)


def _linked_annotation(value: Any, packet: PacketContext) -> dict[str, Any]:
    assignment_id = value.get("assignment_id") if isinstance(value, dict) else None
    if assignment_id not in packet.cases_by_assignment:
        raise ProtocolError("annotation is outside the bound packet")
    return validate_annotation_for_case(
        value,
        packet.cases_by_assignment[assignment_id],
        source_contents=packet.source_contents,
    )


def execute(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "doctor":
        schemas = _schema_records()
        observed_schema_names = {record["name"] for record in schemas}
        schemas_complete = observed_schema_names == EXPECTED_SCHEMAS
        return {
            "version": __version__,
            "protocol_version": PROTOCOL_VERSION,
            "canonicalization_version": CANONICALIZATION_VERSION,
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "offline_mode": True,
            "network_adapter_present": False,
            "provider_api_authorized": False,
            "auth_required": False,
            "schema_count": len(schemas),
            "schemas_complete": schemas_complete,
            "ready": sys.version_info >= (3, 11) and schemas_complete,
        }
    if args.command == "schemas":
        return {"schemas": _schema_records()}
    if args.command == "canonicalize":
        value = load_json(args.input)
        payload = canonical_bytes(value)
        if args.out:
            write_bytes_atomic(args.out, payload + b"\n")
        return {
            "input": str(args.input),
            "out": str(args.out) if args.out else None,
            "bytes": len(payload),
            "sha256": canonical_sha256(value),
            "canonicalization_version": CANONICALIZATION_VERSION,
        }
    if args.command == "packet":
        return _packet_context(args.packet).summary
    if args.command == "annotation":
        packet = _packet_context(args.packet)
        annotation = _linked_annotation(load_json(args.annotation), packet)
        return {
            "assignment_id": annotation["assignment_id"],
            "contributor_id": annotation["contributor_id"],
            "case_sha256": annotation["case_sha256"],
            "annotation_sha256": canonical_sha256(annotation),
            "case_binding_verified": True,
            "valid": True,
        }
    if args.command == "source":
        return validate_source_snapshot(
            load_json(args.manifest), base_dir=args.manifest.parent
        )
    if args.command == "salt":
        return generate_salt(args.out)
    if args.command == "commitment" and args.commitment_command == "create":
        packet = _packet_context(args.packet)
        annotation = _linked_annotation(load_json(args.annotation), packet)
        record = create_commitment(
            annotation, read_salt(args.salt_file), committed_at=args.committed_at
        )
        write_json(args.out, record, exclusive=True)
        return {**record, "out": str(args.out), "annotation_disclosed": False}
    if args.command == "commitment":
        record = validate_commitment(load_json(args.commitment))
        return {
            "commitment_id": record["commitment_id"],
            "assignment_id": record["assignment_id"],
            "contributor_id": record["contributor_id"],
            "valid": True,
        }
    if args.command == "reveal" and args.reveal_command == "create":
        commitment = validate_commitment(load_json(args.commitment))
        packet = _packet_context(args.packet)
        annotation = _linked_annotation(load_json(args.annotation), packet)
        record = create_reveal(
            commitment,
            annotation,
            read_salt(args.salt_file),
            revealed_at=args.revealed_at,
        )
        write_json(args.out, record, exclusive=True)
        return {
            "commitment_id": record["commitment_id"],
            "assignment_id": record["assignment_id"],
            "contributor_id": record["contributor_id"],
            "out": str(args.out),
        }
    if args.command == "reveal":
        reveal = load_json(args.reveal)
        result = verify_reveal(load_json(args.commitment), reveal)
        packet = _packet_context(args.packet)
        _linked_annotation(
            reveal.get("annotation") if isinstance(reveal, dict) else None, packet
        )
        return {**result, "case_binding_verified": True}
    if args.command == "identity":
        record = verify_git_identity(args.repo, args.commit)
        if args.out:
            write_json(args.out, record)
        return {**record, "out": str(args.out) if args.out else None}
    if args.command == "qualification":
        packet = _packet_context(args.packet)
        result = score_qualification(
            load_json(args.key),
            base_dir=args.key.parent,
            submission_path=args.submission,
            packet=packet,
        )
        if args.out:
            write_json(args.out, result)
        return {**result, "out": str(args.out) if args.out else None}
    if args.command == "agreement":
        result = score_agreement(
            args.annotations,
            packet=_packet_context(args.packet),
            strata_path=args.strata,
        )
        if args.out:
            write_json(args.out, result)
        return {**result, "out": str(args.out) if args.out else None}
    raise ProtocolError("unsupported command", code="usage_error")


def _emit_text(command: str, data: dict[str, Any]) -> None:
    if command == "doctor":
        print(
            f"atlas-test {data['version']}: ready={str(data['ready']).lower()} "
            f"offline=true schemas={data['schema_count']} api_authorized=false"
        )
        return
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw_args = list(argv) if argv is not None else sys.argv[1:]
    json_requested = "--json" in raw_args
    command_name = "usage"
    known_commands = {
        "doctor",
        "schemas",
        "canonicalize",
        "packet",
        "annotation",
        "source",
        "salt",
        "commitment",
        "reveal",
        "identity",
        "qualification",
        "agreement",
    }
    for value in raw_args:
        if value in known_commands:
            command_name = value
            break
    try:
        args = parser.parse_args(raw_args)
        command_name = args.command
        data = execute(args)
        envelope = {"ok": True, "command": command_name, "data": data}
        if json_requested:
            print(json.dumps(envelope, ensure_ascii=False, sort_keys=True))
        else:
            _emit_text(command_name, data)
        return 0
    except ProtocolError as exc:
        envelope = {
            "ok": False,
            "command": command_name,
            "error": {"code": exc.code, "message": str(exc)},
        }
        if json_requested:
            print(json.dumps(envelope, ensure_ascii=False, sort_keys=True))
        else:
            print(f"atlas-test: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        envelope = {
            "ok": False,
            "command": command_name,
            "error": {"code": "io_error", "message": str(exc)},
        }
        if json_requested:
            print(json.dumps(envelope, ensure_ascii=False, sort_keys=True))
        else:
            print(f"atlas-test: {exc}", file=sys.stderr)
        return 3
    except Exception:  # noqa: BLE001 - stable CLI boundary must not leak tracebacks
        envelope = {
            "ok": False,
            "command": command_name,
            "error": {
                "code": "internal_error",
                "message": "unexpected internal error; no protocol result was produced",
            },
        }
        if json_requested:
            print(json.dumps(envelope, ensure_ascii=False, sort_keys=True))
        else:
            print(
                "atlas-test: unexpected internal error; no protocol result was produced",
                file=sys.stderr,
            )
        return 4
