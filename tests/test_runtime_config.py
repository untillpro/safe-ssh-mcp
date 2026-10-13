#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "asyncssh>=2.24.1",
#     "mcp>=2,<3",
#     "pyyaml>=6.0",
#     "typing-extensions>=4.12",
# ]
# ///
"""Tests for runtime policy and logging directory configuration."""

import os
import subprocess
import sys
import unittest
from io import TextIOWrapper
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from safe_ssh_mcp import (
    COMMAND_POLICIES,
    LOG_DIR_ENV,
    POLICY_DIR_ENV,
    _resolve_configured_directory,
    configure_logging,
    initialize_command_policies,
    initialize_runtime,
    logger,
)


class RuntimeDirectoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_policies = dict(COMMAND_POLICIES)
        self.original_handlers = list(logger.handlers)
        self.original_level = logger.level
        self.original_propagate = logger.propagate

    def tearDown(self) -> None:
        COMMAND_POLICIES.clear()
        COMMAND_POLICIES.update(self.original_policies)

        self.restore_logging()

    def restore_logging(self) -> None:
        """Close handlers created by a test before temporary paths are removed."""

        current_handlers = list(logger.handlers)
        logger.handlers.clear()
        for handler in current_handlers:
            if handler not in self.original_handlers:
                handler.close()
        logger.handlers.extend(self.original_handlers)
        logger.setLevel(self.original_level)
        logger.propagate = self.original_propagate

    @staticmethod
    def write_policy(directory: Path) -> None:
        directory.mkdir(parents=True)
        (directory / "only.yaml").write_text(
            "probe:\n  mode: permissive\n", encoding="utf-8"
        )

    def test_default_directories_are_beside_the_script(self) -> None:
        with (
            patch.dict(os.environ, {}, clear=False),
            patch("safe_ssh_mcp.SCRIPT_DIR", Path("/application").resolve()),
        ):
            os.environ.pop(POLICY_DIR_ENV, None)
            os.environ.pop(LOG_DIR_ENV, None)
            self.assertEqual(
                _resolve_configured_directory(POLICY_DIR_ENV, "policies"),
                Path("/application/policies").resolve(),
            )
            self.assertEqual(
                _resolve_configured_directory(LOG_DIR_ENV, ".logs"),
                Path("/application/.logs").resolve(),
            )

    def test_relative_and_absolute_overrides_are_resolved(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            absolute_logs = root / "absolute-logs"
            with (
                patch("safe_ssh_mcp.SCRIPT_DIR", root),
                patch.dict(
                    os.environ,
                    {
                        POLICY_DIR_ENV: "configuration/policies",
                        LOG_DIR_ENV: str(absolute_logs),
                    },
                    clear=False,
                ),
            ):
                self.assertEqual(
                    _resolve_configured_directory(POLICY_DIR_ENV, "policies"),
                    root / "configuration" / "policies",
                )
                self.assertEqual(
                    _resolve_configured_directory(LOG_DIR_ENV, ".logs"),
                    absolute_logs,
                )

    def test_empty_environment_value_is_rejected(self) -> None:
        with (
            patch.dict(os.environ, {POLICY_DIR_ENV: "  "}, clear=False),
            self.assertRaisesRegex(ValueError, "must not be empty"),
        ):
            _resolve_configured_directory(POLICY_DIR_ENV, "policies")

    def test_runtime_uses_complete_configured_policy_and_log_directories(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            policy_dir = root / "custom-policies"
            log_dir = root / "runtime-logs"
            self.write_policy(policy_dir)

            with (
                patch("safe_ssh_mcp.SCRIPT_DIR", root),
                patch.dict(
                    os.environ,
                    {
                        POLICY_DIR_ENV: policy_dir.name,
                        LOG_DIR_ENV: log_dir.name,
                    },
                    clear=False,
                ),
            ):
                try:
                    resolved_policy_dir, log_file = initialize_runtime()
                    self.assertEqual(resolved_policy_dir, policy_dir)
                    self.assertEqual(log_file.parent, log_dir)
                    self.assertTrue(log_file.is_file())
                    self.assertEqual(set(COMMAND_POLICIES), {"probe"})
                finally:
                    self.restore_logging()

    def test_missing_configured_policy_directory_fails_closed(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            with (
                patch("safe_ssh_mcp.SCRIPT_DIR", root),
                patch.dict(
                    os.environ, {POLICY_DIR_ENV: "missing-policies"}, clear=False
                ),
                self.assertRaisesRegex(FileNotFoundError, "Policy directory not found"),
            ):
                initialize_command_policies()

    def test_unusable_log_directory_fails_startup(self) -> None:
        with TemporaryDirectory() as temp_dir:
            occupied_path = Path(temp_dir) / "not-a-directory"
            occupied_path.write_text("content", encoding="utf-8")
            with self.assertRaisesRegex(OSError, "Cannot create log directory"):
                configure_logging(occupied_path)

    def test_import_does_not_create_configured_log_directory(self) -> None:
        with TemporaryDirectory() as temp_dir:
            log_dir = Path(temp_dir) / "import-logs"
            environment = os.environ.copy()
            environment[LOG_DIR_ENV] = str(log_dir)
            environment["PYTHONUTF8"] = "1"
            completed: subprocess.CompletedProcess[str] = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import safe_ssh_mcp; print(len(safe_ssh_mcp.COMMAND_POLICIES))",
                ],
                cwd=REPOSITORY_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )

            self.assertEqual(completed.returncode, 0, msg=completed.stderr)
            self.assertEqual(completed.stdout.strip(), "0")
            self.assertFalse(log_dir.exists())

    def test_startup_reports_missing_configured_policy_directory(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            environment = os.environ.copy()
            environment[POLICY_DIR_ENV] = str(root / "missing-policies")
            environment[LOG_DIR_ENV] = str(root / "logs")
            environment["PYTHONUTF8"] = "1"
            completed: subprocess.CompletedProcess[str] = subprocess.run(
                [sys.executable, str(REPOSITORY_ROOT / "safe_ssh_mcp.py")],
                cwd=REPOSITORY_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
                timeout=10,
            )

            self.assertEqual(completed.returncode, 78)
            self.assertIn("safe-ssh-mcp: startup failed:", completed.stderr)
            self.assertIn("Policy directory not found", completed.stderr)


def main() -> None:
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if isinstance(stream, TextIOWrapper):
            stream.reconfigure(encoding="utf-8")
    unittest.main()


if __name__ == "__main__":
    main()
