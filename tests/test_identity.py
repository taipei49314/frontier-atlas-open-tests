from __future__ import annotations

import subprocess
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

from atlas_test.canonical import ProtocolError
from atlas_test.identity import verify_git_identity


class IdentityTests(unittest.TestCase):
    def test_verified_signature_is_evidence_not_github_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / ".git").mkdir()

            def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
                if "rev-parse" in command:
                    return subprocess.CompletedProcess(command, 0, "a" * 40 + "\n", "")
                if "verify-commit" in command:
                    return subprocess.CompletedProcess(command, 0, "", "")
                return subprocess.CompletedProcess(
                    command,
                    0,
                    ("a" * 40)
                    + "\x00user@example.invalid\x00G\x00FINGERPRINT\x00Test User\n",
                    "",
                )

            result = verify_git_identity(repo, "a" * 7, runner=runner)
            self.assertTrue(result["cryptographic_signature_verified"])
            self.assertEqual(
                result["github_account_mapping_status"], "not_verified_offline"
            )

    def test_unsigned_commit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / ".git").mkdir()

            def runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
                if "rev-parse" in command:
                    return subprocess.CompletedProcess(command, 0, "b" * 40 + "\n", "")
                return subprocess.CompletedProcess(command, 1, "", "no signature")

            with self.assertRaisesRegex(ProtocolError, "signature"):
                verify_git_identity(repo, "b" * 7, runner=runner)


if __name__ == "__main__":
    unittest.main()
