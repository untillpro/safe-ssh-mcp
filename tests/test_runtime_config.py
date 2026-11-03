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
    CONFIG_DIR_ENV,
    _resolve_configured_directory,
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

    @classmethod
    def write_configuration(
        cls,
        directory: Path,
        config_text: str = "version: 1\n",
        *,
        include_policy: bool = True,
    ) -> None:
        directory.mkdir(parents=True)
        (directory / "config.yaml").write_text(config_text, encoding="utf-8")
        if include_policy:
            cls.write_policy(directory / "policies")

    @staticmethod
    def subprocess_environment() -> dict[str, str]:
        environment: dict[str, str] = os.environ.copy()
        environment.pop(CONFIG_DIR_ENV, None)
        environment["PYTHONUTF8"] = "1"
        return environment

    def test_default_configuration_directory_is_beside_the_script(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            config_dir = root / "config"
            self.write_configuration(config_dir)
            with (
                patch("safe_ssh_mcp.SCRIPT_DIR", root),
                patch.dict(os.environ, {}, clear=True),
            ):
                try:
                    resolved_policy_dir, log_file = initialize_runtime()
                    self.assertEqual(resolved_policy_dir, config_dir / "policies")
                    self.assertEqual(log_file.parent, config_dir / ".logs")
                    self.assertTrue(log_file.is_file())
                    self.assertEqual(set(COMMAND_POLICIES), {"probe"})
                finally:
                    self.restore_logging()

    def test_relative_and_absolute_configuration_directories_are_resolved(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            relative_config_dir = root / "relative-config"
            absolute_config_dir = root / "absolute-config"
            self.write_configuration(relative_config_dir)
            self.write_configuration(absolute_config_dir)

            cases = (
                ("relative", relative_config_dir.name, relative_config_dir),
                ("absolute", str(absolute_config_dir), absolute_config_dir),
            )
            for name, configured_value, expected_config_dir in cases:
                with (
                    self.subTest(name=name),
                    patch("safe_ssh_mcp.SCRIPT_DIR", root),
                    patch.dict(
                        os.environ,
                        {CONFIG_DIR_ENV: configured_value},
                        clear=True,
                    ),
                ):
                    try:
                        resolved_policy_dir, log_file = initialize_runtime()
                        self.assertEqual(
                            resolved_policy_dir, expected_config_dir / "policies"
                        )
                        self.assertEqual(log_file.parent, expected_config_dir / ".logs")
                    finally:
                        self.restore_logging()

    def test_log_directory_is_resolved_from_configuration_directory(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            config_dir = root / "custom-config"
            self.write_configuration(
                config_dir,
                "version: 1\nlogging:\n  directory: runtime/logs\n",
            )
            with (
                patch("safe_ssh_mcp.SCRIPT_DIR", root),
                patch.dict(os.environ, {CONFIG_DIR_ENV: str(config_dir)}, clear=True),
            ):
                try:
                    _, log_file = initialize_runtime()
                    self.assertEqual(log_file.parent, config_dir / "runtime" / "logs")
                finally:
                    self.restore_logging()

    def test_empty_environment_value_is_rejected(self) -> None:
        with (
            patch.dict(os.environ, {CONFIG_DIR_ENV: "  "}, clear=True),
            self.assertRaisesRegex(ValueError, "must not be empty"),
        ):
            _resolve_configured_directory(CONFIG_DIR_ENV, "config")

    def test_configuration_file_is_required(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            config_dir = root / "missing-config-file"
            config_dir.mkdir()
            with (
                patch("safe_ssh_mcp.SCRIPT_DIR", root),
                patch.dict(os.environ, {CONFIG_DIR_ENV: str(config_dir)}, clear=True),
                self.assertRaisesRegex(
                    FileNotFoundError, "Configuration file not found"
                ),
            ):
                initialize_runtime()

    def test_configuration_file_is_strictly_validated(self) -> None:
        invalid_configurations = (
            ("malformed", "version: [\n", "Failed to parse"),
            ("duplicate", "version: 1\nversion: 1\n", "Duplicate YAML key"),
            ("unknown", "version: 1\nother: true\n", "unknown field"),
            ("unsupported", "version: 2\n", "must be the integer 1"),
            (
                "unknown logging",
                "version: 1\nlogging:\n  other: .logs\n",
                "unknown field",
            ),
            (
                "empty logging directory",
                "version: 1\nlogging:\n  directory: '  '\n",
                "must be a non-empty string",
            ),
        )
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            for name, config_text, expected_error in invalid_configurations:
                config_dir = root / name.replace(" ", "-")
                self.write_configuration(config_dir, config_text)
                with (
                    self.subTest(name=name),
                    patch("safe_ssh_mcp.SCRIPT_DIR", root),
                    patch.dict(
                        os.environ, {CONFIG_DIR_ENV: str(config_dir)}, clear=True
                    ),
                    self.assertRaisesRegex(ValueError, expected_error),
                ):
                    initialize_runtime()

    def test_missing_policy_directory_fails_closed(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            config_dir = root / "missing-policies"
            self.write_configuration(config_dir, include_policy=False)
            with (
                patch("safe_ssh_mcp.SCRIPT_DIR", root),
                patch.dict(os.environ, {CONFIG_DIR_ENV: str(config_dir)}, clear=True),
            ):
                try:
                    with self.assertRaisesRegex(
                        FileNotFoundError, "Policy directory not found"
                    ):
                        initialize_runtime()
                finally:
                    self.restore_logging()

    def test_unusable_log_directory_fails_startup(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir).resolve() / "config"
            self.write_configuration(config_dir)
            occupied_path = config_dir / ".logs"
            occupied_path.write_text("content", encoding="utf-8")
            with (
                patch.dict(os.environ, {CONFIG_DIR_ENV: str(config_dir)}, clear=True),
                self.assertRaisesRegex(OSError, "Cannot create log directory"),
            ):
                initialize_runtime()

    def test_import_does_not_create_configured_log_directory(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir).resolve() / "config"
            log_dir = config_dir / ".logs"
            environment = self.subprocess_environment()
            environment[CONFIG_DIR_ENV] = str(config_dir)
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

    def test_startup_reports_missing_policy_directory(self) -> None:
        with TemporaryDirectory() as temp_dir:
            config_dir = Path(temp_dir).resolve() / "config"
            self.write_configuration(config_dir, include_policy=False)
            environment = self.subprocess_environment()
            environment[CONFIG_DIR_ENV] = str(config_dir)
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
