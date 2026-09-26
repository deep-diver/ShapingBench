from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReleaseTests(unittest.TestCase):
    def test_inventory_and_payloads(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/verify_release.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_public_evaluator_help(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "evaluation/run.py"), "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--snapshot", result.stdout)


if __name__ == "__main__":
    unittest.main()
