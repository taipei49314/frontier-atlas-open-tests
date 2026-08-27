from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from atlas_test.canonical import ProtocolError
from atlas_test.commit_reveal import (
    create_commitment,
    create_reveal,
    generate_salt,
    read_salt,
    validate_commitment,
    verify_reveal,
)
from tests.helpers import make_annotation


class CommitRevealTests(unittest.TestCase):
    SALT = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"

    def test_round_trip_does_not_disclose_annotation_in_commitment(self) -> None:
        annotation = make_annotation()
        commitment = create_commitment(
            annotation, self.SALT, committed_at="2026-08-27T08:01:00Z"
        )
        self.assertNotIn("annotation", commitment)
        self.assertNotIn("salt", commitment)
        validate_commitment(commitment)
        reveal = create_reveal(
            commitment,
            annotation,
            self.SALT,
            revealed_at="2026-08-27T08:02:00Z",
        )
        result = verify_reveal(commitment, reveal)
        self.assertTrue(result["valid"])

    def test_annotation_tamper_fails(self) -> None:
        annotation = make_annotation()
        commitment = create_commitment(
            annotation, self.SALT, committed_at="2026-08-27T08:01:00Z"
        )
        reveal = create_reveal(
            commitment,
            annotation,
            self.SALT,
            revealed_at="2026-08-27T08:02:00Z",
        )
        reveal["annotation"]["notes"] = "tampered"
        with self.assertRaisesRegex(ProtocolError, "digest"):
            verify_reveal(commitment, reveal)

    def test_salt_and_commitment_record_tamper_fail(self) -> None:
        annotation = make_annotation()
        commitment = create_commitment(
            annotation, self.SALT, committed_at="2026-08-27T08:01:00Z"
        )
        reveal = create_reveal(
            commitment,
            annotation,
            self.SALT,
            revealed_at="2026-08-27T08:02:00Z",
        )
        wrong_salt = copy.deepcopy(reveal)
        wrong_salt["salt"] = "Z" * 40
        with self.assertRaisesRegex(ProtocolError, "digest"):
            verify_reveal(commitment, wrong_salt)
        changed_commitment = copy.deepcopy(commitment)
        changed_commitment["committed_at"] = "2026-08-27T08:01:30Z"
        with self.assertRaisesRegex(ProtocolError, "bind"):
            verify_reveal(changed_commitment, reveal)

    def test_identity_and_time_are_bound(self) -> None:
        annotation = make_annotation()
        commitment = create_commitment(
            annotation, self.SALT, committed_at="2026-08-27T08:01:00Z"
        )
        other = make_annotation(contributor_id="contributor-b")
        with self.assertRaisesRegex(ProtocolError, "contributor"):
            create_reveal(
                commitment, other, self.SALT, revealed_at="2026-08-27T08:02:00Z"
            )
        with self.assertRaisesRegex(ProtocolError, "predate"):
            create_reveal(
                commitment,
                annotation,
                self.SALT,
                revealed_at="2026-08-27T08:00:30Z",
            )

    def test_salt_generation_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "salt.txt"
            generate_salt(path)
            self.assertGreaterEqual(len(read_salt(path)), 32)
            with self.assertRaisesRegex(ProtocolError, "overwrite"):
                generate_salt(path)


if __name__ == "__main__":
    unittest.main()
