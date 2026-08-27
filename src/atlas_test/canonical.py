"""Strict canonical JSON and file helpers for the public protocol."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

CANONICALIZATION_VERSION = "atlas-canonical-json-v1"
PROTOCOL_VERSION = "frontier-atlas-open-test-v1"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_JSONL_BYTES = 256 * 1024 * 1024


class ProtocolError(ValueError):
    """Stable, user-safe protocol error."""

    def __init__(self, message: str, *, code: str = "validation_error") -> None:
        super().__init__(message)
        self.code = code


def _reject_float(value: str) -> None:
    raise ProtocolError(f"floating-point JSON numbers are forbidden: {value}")


def _reject_constant(value: str) -> None:
    raise ProtocolError(f"non-finite JSON values are forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        if path.stat().st_size > _MAX_JSON_BYTES:
            raise ProtocolError(f"JSON file exceeds {_MAX_JSON_BYTES} bytes: {path}")
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ProtocolError(
            f"cannot read UTF-8 JSON {path}: {exc}", code="io_error"
        ) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ProtocolError(
            f"invalid JSON in {path} at line {exc.lineno} column {exc.colno}"
        ) from exc
    validate_json_value(value)
    return value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        if path.stat().st_size > _MAX_JSONL_BYTES:
            raise ProtocolError(f"JSONL file exceeds {_MAX_JSONL_BYTES} bytes: {path}")
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ProtocolError(
            f"cannot read UTF-8 JSONL {path}: {exc}", code="io_error"
        ) from exc
    rows: list[dict[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            raise ProtocolError(f"blank JSONL line at {path}:{index}")
        try:
            value = json.loads(
                line,
                object_pairs_hook=_unique_object,
                parse_float=_reject_float,
                parse_constant=_reject_constant,
            )
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"invalid JSONL at {path}:{index}: {exc.msg}") from exc
        validate_json_value(value)
        if not isinstance(value, dict):
            raise ProtocolError(f"JSONL row must be an object at {path}:{index}")
        rows.append(value)
    return rows


def validate_json_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise ProtocolError(f"floating-point value forbidden at {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolError(f"non-text object key at {path}")
            validate_json_value(item, f"{path}.{key}")
        return
    raise ProtocolError(f"unsupported JSON value at {path}: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    validate_json_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ProtocolError(f"cannot hash {path}: {exc}", code="io_error") from exc
    return digest.hexdigest()


def write_json(path: Path, value: Any, *, exclusive: bool = False) -> None:
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    if exclusive:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise ProtocolError(
                f"refusing to overwrite {path}: {exc}", code="io_error"
            ) from exc
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
        return
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            handle.write(payload)
        os.replace(temporary, path)
    except OSError as exc:
        raise ProtocolError(f"cannot write {path}: {exc}", code="io_error") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def write_bytes_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
        os.replace(temporary, path)
    except OSError as exc:
        raise ProtocolError(f"cannot write {path}: {exc}", code="io_error") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def expect_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolError(f"{name} must be an object")
    return value


def expect_exact_fields(
    value: dict[str, Any], expected: Iterable[str], name: str
) -> None:
    expected_set = set(expected)
    missing = sorted(expected_set - set(value))
    extra = sorted(set(value) - expected_set)
    if missing or extra:
        raise ProtocolError(f"{name} fields mismatch; missing={missing}, extra={extra}")


def expect_identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ProtocolError(f"{name} must be a protocol identifier")
    return value


def expect_sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ProtocolError(f"{name} must be a lowercase SHA-256 digest")
    return value


def expect_text(
    value: Any, name: str, *, allow_empty: bool = False, maximum: int = 200_000
) -> str:
    if not isinstance(value, str):
        raise ProtocolError(f"{name} must be text")
    if not allow_empty and not value.strip():
        raise ProtocolError(f"{name} must not be empty")
    if len(value) > maximum:
        raise ProtocolError(f"{name} exceeds {maximum} characters")
    return value


def expect_int(
    value: Any,
    name: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ProtocolError(f"{name} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ProtocolError(f"{name} must be an integer <= {maximum}")
    return value


def expect_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ProtocolError(f"{name} must be a boolean")
    return value


def expect_enum(value: Any, allowed: set[str], name: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ProtocolError(f"{name} must be one of {sorted(allowed)}")
    return value


def expect_utc_timestamp(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ProtocolError(f"{name} must be an ISO-8601 UTC timestamp ending in Z")
    try:
        datetime.fromisoformat(value)
    except ValueError as exc:
        raise ProtocolError(f"{name} is not a valid ISO-8601 timestamp") from exc
    return value


def contained_path(base: Path, relative: Any, name: str) -> Path:
    text = expect_text(relative, name, maximum=500)
    candidate = Path(text)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ProtocolError(f"{name} must stay within the packet directory")
    root = base.resolve()
    resolved = (base / candidate).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ProtocolError(f"{name} escapes the packet directory") from exc
    return resolved
