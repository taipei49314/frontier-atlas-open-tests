from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from atlas_test.canonical import (
    ProtocolError,
    canonical_bytes,
    canonical_sha256,
    load_json,
)


class CanonicalTests(unittest.TestCase):
    def test_key_order_and_whitespace_do_not_change_hash(self) -> None:
        left = {"b": [2, 1], "a": "中文"}
        right = {"a": "中文", "b": [2, 1]}
        self.assertEqual(canonical_sha256(left), canonical_sha256(right))
        self.assertEqual(
            canonical_bytes(left), b'{"a":"\xe4\xb8\xad\xe6\x96\x87","b":[2,1]}'
        )

    def test_duplicate_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"a":1,"a":2}', encoding="utf-8")
            with self.assertRaisesRegex(ProtocolError, "duplicate JSON key"):
                load_json(path)

    def test_float_and_nan_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for name, payload in (
                ("float.json", '{"v":1.5}'),
                ("nan.json", '{"v":NaN}'),
            ):
                path = Path(directory) / name
                path.write_text(payload, encoding="utf-8")
                with self.assertRaises(ProtocolError):
                    load_json(path)


if __name__ == "__main__":
    unittest.main()
