from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from atlas_test.cli import main
from tests.helpers import make_annotation, make_case, write_json, write_packet


class CliTests(unittest.TestCase):
    def _run_json(self, argv: list[str]) -> tuple[int, dict]:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["--json", *argv])
        return code, json.loads(output.getvalue())

    def test_doctor_is_offline_and_ready(self) -> None:
        code, payload = self._run_json(["doctor"])
        self.assertEqual(code, 0)
        self.assertTrue(payload["data"]["ready"])
        self.assertFalse(payload["data"]["network_adapter_present"])
        self.assertFalse(payload["data"]["provider_api_authorized"])

    def test_machine_readable_validation_error_has_no_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packet_path, _ = write_packet(root, [make_case()])
            path = root / "bad.json"
            path.write_text('{"unknown":true}', encoding="utf-8")
            code, payload = self._run_json(
                [
                    "annotation",
                    "validate",
                    "--annotation",
                    str(path),
                    "--packet",
                    str(packet_path),
                ]
            )
            self.assertEqual(code, 2)
            self.assertFalse(payload["ok"])
            self.assertEqual(payload["error"]["code"], "validation_error")
            self.assertNotIn("traceback", json.dumps(payload).lower())

    def test_machine_readable_usage_error_does_not_exit_parser(self) -> None:
        code, payload = self._run_json(["annotation", "validate"])
        self.assertEqual(code, 2)
        self.assertEqual(payload["command"], "annotation")
        self.assertEqual(payload["error"]["code"], "usage_error")

    def test_commitment_output_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case = make_case()
            packet_path, _ = write_packet(root, [case])
            annotation = root / "annotation.json"
            salt = root / "salt.txt"
            out = root / "commitment.json"
            write_json(annotation, make_annotation(case=case))
            salt.write_text(
                "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG\n", encoding="utf-8"
            )
            argv = [
                "commitment",
                "create",
                "--annotation",
                str(annotation),
                "--packet",
                str(packet_path),
                "--salt-file",
                str(salt),
                "--committed-at",
                "2026-08-27T08:01:00Z",
                "--out",
                str(out),
            ]
            first, _ = self._run_json(argv)
            second, payload = self._run_json(argv)
            self.assertEqual(first, 0)
            self.assertEqual(second, 2)
            self.assertEqual(payload["error"]["code"], "io_error")


if __name__ == "__main__":
    unittest.main()
