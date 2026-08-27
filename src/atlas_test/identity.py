"""Offline Git commit-signature evidence; GitHub account mapping stays external."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .canonical import PROTOCOL_VERSION, ProtocolError

_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def _run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def verify_git_identity(
    repo: Path, commit: str, *, runner: Runner = _run
) -> dict[str, Any]:
    if _COMMIT_RE.fullmatch(commit) is None:
        raise ProtocolError("commit must be a 7-64 character hexadecimal Git object ID")
    if not (repo / ".git").exists():
        raise ProtocolError(f"not a Git repository: {repo}", code="io_error")
    resolved = runner(
        ["git", "-C", str(repo), "rev-parse", "--verify", f"{commit}^{{commit}}"]
    )
    if resolved.returncode != 0:
        raise ProtocolError("Git commit cannot be resolved", code="identity_unverified")
    full = resolved.stdout.strip().lower()
    verified = runner(["git", "-C", str(repo), "verify-commit", "--raw", full])
    if verified.returncode != 0:
        raise ProtocolError(
            "Git commit signature is absent or invalid", code="identity_unverified"
        )
    shown = runner(
        [
            "git",
            "-C",
            str(repo),
            "show",
            "-s",
            "--format=%H%x00%ae%x00%G?%x00%GF%x00%GS",
            full,
        ]
    )
    if shown.returncode != 0:
        raise ProtocolError(
            "cannot inspect verified Git commit", code="identity_unverified"
        )
    parts = shown.stdout.rstrip("\r\n").split("\x00")
    if len(parts) != 5 or parts[2] not in {"G", "U"}:
        raise ProtocolError(
            "Git reports a non-good signature", code="identity_unverified"
        )
    return {
        "schema_version": 1,
        "protocol_version": PROTOCOL_VERSION,
        "commit_sha": parts[0].lower(),
        "author_email": parts[1],
        "git_signature_status": parts[2],
        "signer_fingerprint": parts[3],
        "signer_identity": parts[4],
        "cryptographic_signature_verified": True,
        "github_account_mapping_status": "not_verified_offline",
    }
