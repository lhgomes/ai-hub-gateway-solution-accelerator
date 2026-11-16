"""Offline tests for the optional read-only Azure gateway smoke runner."""
import importlib.util
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/smoke_test_entra_gateway.py"
spec = importlib.util.spec_from_file_location("smoke_runner", SCRIPT)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class SmokeRunnerTests(unittest.TestCase):
    def test_only_explicit_https_url_is_allowed(self):
        for value in ("http://example.com/api", "https://user:pass@example.com",
                      "https://example.com/api?token=secret", "https://example.com/api#fragment"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                smoke.endpoint(value)
        self.assertEqual(smoke.endpoint("https://example.com/models"), "https://example.com/models")

    def test_negative_and_positive_security_statuses(self):
        expected = [401, 401, 403, 200]
        with patch.object(smoke, "invoke", side_effect=expected) as fake:
            with redirect_stdout(io.StringIO()) as out:
                result = smoke.run("https://example.com/models", "secret-authorized",
                                   "secret-denied")
            self.assertEqual(result, 0)
            self.assertEqual(fake.call_count, 4)
            self.assertNotIn("secret-", out.getvalue())

    def test_security_regression_is_reported(self):
        with patch.object(smoke, "invoke", side_effect=[200, 401]):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(smoke.run("https://example.com/models"), 1)


if __name__ == "__main__":
    unittest.main()
