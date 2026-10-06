"""Smoke tests that execute the package the way a user does.

The unit suites import `main()` directly, which never runs the
`if __name__ == "__main__":` block. A real bug once lived exactly there — an
automated fix appended `from exc` to `raise SystemExit(main())`, referencing
a name that does not exist at module scope. Every test passed; running the
command would have raised NameError.

So these run the entry points as subprocesses. They are slow relative to the
rest of the suite and they cover the one path nothing else does.
"""

import subprocess
import sys
import unittest


class TestEntryPoints(unittest.TestCase):
    def run_module(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "tripwire", *args],
            capture_output=True,
            text=True,
            timeout=120,
        )

    def test_module_executes_as_main(self):
        result = self.run_module("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("tripwire", result.stdout + result.stderr)

    def test_help_executes_as_main(self):
        result = self.run_module("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage", (result.stdout + result.stderr).lower())

    def test_reported_version_matches_the_package_metadata(self):
        """A release bump has to land in both places, or `--version` lies."""
        import os

        from tripwire import __version__
        from tripwire.tomlparse import loads

        pyproject = os.path.join(os.path.dirname(__file__), os.pardir, "pyproject.toml")
        with open(pyproject, encoding="utf-8") as handle:
            declared = loads(handle.read())["project"]["version"]
        self.assertEqual(__version__, declared)
        result = self.run_module("--version")
        self.assertIn(declared, result.stdout + result.stderr)

    def test_no_warnings_on_import(self):
        """A SyntaxWarning from an invalid escape would surface here."""
        result = subprocess.run(
            [sys.executable, "-W", "error::SyntaxWarning", "-c", "import tripwire"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
