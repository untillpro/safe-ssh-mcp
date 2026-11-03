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
"""Regression tests for structured pipeline validation and log rendering."""

import os
import sys
import unittest
from collections.abc import Callable
from io import TextIOWrapper
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from safe_ssh_mcp import (
    CommandStage,
    _cleanup_expired_logs,
    _PresentedHostKeyObserver,
    _process_is_running,
    _windows_process_is_running,
    close_ssh_connections,
    configure_logging,
    execute_ssh_command,
    get_ssh_connection,
    initialize_command_policies,
    logger,
    render_pipeline,
    ssh_connection_locks,
    ssh_connections,
    validate_pipeline,
)

initialize_command_policies(REPOSITORY_ROOT / "config" / "policies")


def single(command: str, *arguments: str) -> list[CommandStage]:
    return [{"command": command, "arguments": list(arguments)}]


class LogRetentionTests(unittest.TestCase):
    now_ns = 2_000_000_000_000_000_000
    day_ns = 86_400_000_000_000

    def setUp(self) -> None:
        temporary_directory = TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.log_dir = Path(temporary_directory.name).resolve()
        self.current_log = self.log_dir / f"2601010000-{os.getpid()}.log"
        self.original_handlers = list(logger.handlers)
        self.original_level = logger.level
        self.original_propagate = logger.propagate
        self.addCleanup(self.restore_logging)

    def restore_logging(self) -> None:
        current_handlers = list(logger.handlers)
        logger.handlers.clear()
        for handler in current_handlers:
            if handler not in self.original_handlers:
                handler.close()
        logger.handlers.extend(self.original_handlers)
        logger.setLevel(self.original_level)
        logger.propagate = self.original_propagate

    def write_log(self, name: str, age_days: int) -> Path:
        path = self.log_dir / name
        path.write_text("session log é\n", encoding="utf-8")
        modified_ns = self.now_ns - age_days * self.day_ns
        os.utime(path, ns=(modified_ns, modified_ns))
        return path

    def cleanup(self, retention_days: int = 30) -> None:
        with patch("safe_ssh_mcp.time.time_ns", return_value=self.now_ns):
            _cleanup_expired_logs(self.log_dir, self.current_log, retention_days)

    def test_only_logs_older_than_the_cutoff_are_deleted(self) -> None:
        expired = self.write_log("2601010000-1111.log", 31)
        boundary = self.write_log("2601010000-2222.log", 30)
        recent = self.write_log("2601010000-3333.log", 29)
        with patch("safe_ssh_mcp._process_is_running", return_value=False):
            self.cleanup()
        self.assertFalse(expired.exists())
        self.assertTrue(boundary.exists())
        self.assertTrue(recent.exists())

    def test_modification_time_takes_precedence_over_filename_date(self) -> None:
        old_name = self.write_log("0001010000-1111.log", 1)
        future_name = self.write_log("9901010000-2222.log", 31)
        with patch("safe_ssh_mcp._process_is_running", return_value=False):
            self.cleanup()
        self.assertTrue(old_name.exists())
        self.assertFalse(future_name.exists())

    def test_current_active_and_uncertain_process_logs_are_preserved(self) -> None:
        current = self.write_log(self.current_log.name, 31)
        active = self.write_log("2601010000-1111.log", 31)
        uncertain = self.write_log("2601010000-2222.log", 31)

        def process_state(pid: int) -> bool | None:
            self.assertIn(pid, (1111, 2222))
            return True if pid == 1111 else None

        with patch("safe_ssh_mcp._process_is_running", side_effect=process_state):
            self.cleanup()
        for path in (current, active, uncertain):
            self.assertTrue(path.exists())

    def test_unrelated_files_and_subdirectories_are_preserved(self) -> None:
        unrelated = [
            self.write_log(name, 31)
            for name in ("other.log", "2601010000-1111.log.1", "2601010000-0.log")
        ]
        directory = self.log_dir / "2601010000-2222.log"
        directory.mkdir()
        nested = directory / "2601010000-3333.log"
        nested.write_text("nested log", encoding="utf-8")
        old_ns = self.now_ns - 31 * self.day_ns
        os.utime(directory, ns=(old_ns, old_ns))
        with patch("safe_ssh_mcp._process_is_running") as process_state:
            self.cleanup()
        process_state.assert_not_called()
        for path in (*unrelated, directory, nested):
            self.assertTrue(path.exists())

    def test_symlink_and_target_are_preserved(self) -> None:
        target = self.write_log("unrelated.txt", 31)
        link = self.log_dir / "2601010000-1111.log"
        try:
            link.symlink_to(target)
        except OSError:
            # Windows may require Developer Mode or elevation to create symlinks.
            self.skipTest("Creating symlinks is unavailable")
        with patch("safe_ssh_mcp._process_is_running") as process_state:
            self.cleanup()
        process_state.assert_not_called()
        self.assertTrue(link.is_symlink())
        self.assertEqual(target.read_text(encoding="utf-8"), "session log é\n")

    def test_cleanup_continues_after_a_deletion_failure(self) -> None:
        expired = self.write_log("2601010000-1111.log", 31)
        other = self.write_log("2601010000-2222.log", 31)
        original_unlink = Path.unlink

        def unlink(path: Path, missing_ok: bool = False) -> None:
            if path == expired:
                raise PermissionError("file is busy")
            original_unlink(path, missing_ok=missing_ok)

        with (
            patch("safe_ssh_mcp._process_is_running", return_value=False),
            patch.object(Path, "unlink", new=unlink),
            self.assertLogs(logger, level="WARNING") as captured,
        ):
            self.cleanup()
        self.assertTrue(expired.exists())
        self.assertFalse(other.exists())
        self.assertIn("file is busy", captured.output[0])

    def test_concurrent_removal_does_not_warn(self) -> None:
        self.write_log("2601010000-1111.log", 31)
        with (
            patch("safe_ssh_mcp._process_is_running", return_value=False),
            patch.object(Path, "unlink", side_effect=FileNotFoundError),
            patch("safe_ssh_mcp.logger.warning") as warning,
        ):
            self.cleanup()
        warning.assert_not_called()

    def test_scan_failure_warns_without_raising(self) -> None:
        with (
            patch.object(Path, "iterdir", side_effect=PermissionError("cannot list")),
            self.assertLogs(logger, level="WARNING") as captured,
        ):
            self.cleanup()
        self.assertIn("cannot list", captured.output[0])

    def test_large_retention_value_preserves_logs_without_overflow(self) -> None:
        path = self.write_log("2601010000-1111.log", 31)
        with patch("safe_ssh_mcp._process_is_running") as process_state:
            self.cleanup(10**100)
        process_state.assert_not_called()
        self.assertTrue(path.exists())

    def test_startup_cleanup_failure_is_logged_and_utf8_logging_still_works(
        self,
    ) -> None:
        expired = self.write_log("2601010000-1111.log", 31)
        with (
            patch("safe_ssh_mcp.time.time_ns", return_value=self.now_ns),
            patch("safe_ssh_mcp._process_is_running", return_value=False),
            patch.object(Path, "unlink", side_effect=PermissionError("file is busy")),
        ):
            log_file = configure_logging(self.log_dir, retention_days=30)
        logger.info("UTF-8: café")
        self.assertTrue(expired.exists())
        contents = log_file.read_text(encoding="utf-8")
        self.assertIn("Cannot clean up log file", contents)
        self.assertIn("UTF-8: café", contents)


class ProcessLivenessTests(unittest.TestCase):
    def test_current_process_and_invalid_pids_never_send_signals(self) -> None:
        with patch("safe_ssh_mcp.os.kill") as kill:
            self.assertTrue(_process_is_running(os.getpid()))
            self.assertIsNone(_process_is_running(0))
            self.assertIsNone(_process_is_running(-1))
        kill.assert_not_called()

    def test_posix_process_checks_are_conservative(self) -> None:
        cases: tuple[tuple[Exception | None, bool | None], ...] = (
            (None, True),
            (ProcessLookupError(), False),
            (PermissionError(), None),
            (OSError(), None),
            (OverflowError(), None),
        )
        for error, expected in cases:
            with (
                self.subTest(error=error),
                patch("safe_ssh_mcp.sys.platform", "linux"),
                patch("safe_ssh_mcp.os.name", "posix"),
                patch("safe_ssh_mcp.os.kill", side_effect=error) as kill,
            ):
                self.assertIs(_process_is_running(123456789), expected)
                kill.assert_called_once_with(123456789, 0)

    def test_windows_never_calls_os_kill(self) -> None:
        with (
            patch("safe_ssh_mcp.sys.platform", "win32"),
            patch("safe_ssh_mcp._windows_process_is_running", return_value=None),
            patch("safe_ssh_mcp.os.kill") as kill,
        ):
            self.assertIsNone(_process_is_running(123456789))
        kill.assert_not_called()

    def test_windows_process_handle_is_closed(self) -> None:
        with patch("safe_ssh_mcp.ctypes.WinDLL", create=True) as library:
            kernel32 = library.return_value
            kernel32.OpenProcess.return_value = 123
            self.assertTrue(_windows_process_is_running(123456789))
            kernel32.OpenProcess.assert_called_once_with(0x1000, False, 123456789)
            kernel32.CloseHandle.assert_called_once_with(123)

    def test_windows_only_a_missing_pid_is_inactive(self) -> None:
        for error_code, expected in ((87, False), (5, None), (0, None)):
            with (
                self.subTest(error_code=error_code),
                patch("safe_ssh_mcp.ctypes.WinDLL", create=True) as library,
                patch(
                    "safe_ssh_mcp.ctypes.get_last_error",
                    return_value=error_code,
                    create=True,
                ),
            ):
                library.return_value.OpenProcess.return_value = None
                self.assertIs(_windows_process_is_running(123456789), expected)
                library.return_value.CloseHandle.assert_not_called()

    def test_windows_api_failure_and_oversized_pid_are_uncertain(self) -> None:
        with patch(
            "safe_ssh_mcp.ctypes.WinDLL", side_effect=OSError, create=True
        ) as library:
            self.assertIsNone(_windows_process_is_running(123456789))
            self.assertIsNone(_windows_process_is_running(0x100000000))
            library.assert_called_once()

    @unittest.skipUnless(sys.platform == "win32", "Windows process API smoke test")
    def test_windows_api_preserves_a_real_running_process(self) -> None:
        self.assertTrue(_windows_process_is_running(os.getpid()))


class PipelineValidationExamples(unittest.TestCase):
    def test_read_only_and_modifying_examples(self) -> None:
        cases: tuple[tuple[list[CommandStage], bool], ...] = (
            (single("ls", "-la"), True),
            (single("cat", "/etc/passwd"), True),
            (single("rm", "-rf", "/tmp/test"), False),
            (single("systemctl", "restart", "nginx"), False),
            (single("find", "/tmp", "-delete"), False),
            (single("tar", "-xzf", "archive.tar.gz"), False),
            (single("grep", "error|warning", "/var/log/syslog"), True),
            (single("ping", "-c", "5", "google.com"), True),
            (single("ping", "google.com"), False),
        )
        for pipeline, expected in cases:
            with self.subTest(pipeline=pipeline):
                accepted, reason = validate_pipeline(pipeline)
                self.assertEqual(accepted, expected, msg=reason)

    def test_rendering_is_deterministic(self) -> None:
        pipeline: list[CommandStage] = [
            {"command": "journalctl", "arguments": ["-u", "app", "-n", "100"]},
            {"command": "grep", "arguments": ["error|warning"]},
        ]
        self.assertEqual(
            render_pipeline(pipeline),
            "journalctl -u app -n 100 | grep 'error|warning'",
        )


class PipelineLoggingTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def ssh_client() -> MagicMock:
        client: MagicMock = MagicMock()
        client.get_extra_info.return_value = "test"
        client.is_closed.return_value = False
        return client

    async def test_multiline_argument_is_escaped_in_log(self) -> None:
        pipeline = single("grep", "first\nsecond", "/var/log/app.log")
        with (
            patch("safe_ssh_mcp.get_ssh_connection", return_value=self.ssh_client()),
            patch(
                "safe_ssh_mcp._run_bounded_process",
                new=AsyncMock(return_value=(b"ok", b"", 0, False, False)),
            ),
            patch("safe_ssh_mcp.logger.info") as info,
        ):
            await execute_ssh_command("host", pipeline)

        messages = [str(call.args[0]) for call in info.call_args_list]
        command_message = next(message for message in messages if "grep" in message)
        self.assertIn("first\\x0asecond", command_message)
        self.assertNotIn("first\nsecond", command_message)

    async def test_truncation_and_unavailable_status_are_logged(self) -> None:
        with (
            patch("safe_ssh_mcp.get_ssh_connection", return_value=self.ssh_client()),
            patch(
                "safe_ssh_mcp._run_bounded_process",
                new=AsyncMock(return_value=(b"output", b"", None, True, False)),
            ),
            patch("safe_ssh_mcp.logger.info") as info,
        ):
            await execute_ssh_command("host", single("uptime"))

        messages = [str(call.args[0]) for call in info.call_args_list]
        self.assertTrue(any("stdout truncated" in message for message in messages))
        self.assertTrue(
            any("exit_status=unavailable" in message for message in messages)
        )

    async def test_timeout_is_logged_without_transport_details(self) -> None:
        with (
            patch("safe_ssh_mcp.get_ssh_connection", return_value=self.ssh_client()),
            patch(
                "safe_ssh_mcp._run_bounded_process",
                new=AsyncMock(side_effect=TimeoutError("credential=do-not-log")),
            ),
            patch("safe_ssh_mcp.logger.warning") as warning,
            self.assertRaisesRegex(TimeoutError, "timed out"),
        ):
            await execute_ssh_command("host", single("uptime"))

        message = str(warning.call_args.args[0])
        self.assertIn("TIMEOUT", message)
        self.assertNotIn("credential", message)

    async def test_pool_reuse_and_shutdown_are_logged(self) -> None:
        connection: MagicMock = MagicMock()
        connection.is_closed.return_value = False
        connection.wait_closed = AsyncMock()
        ssh_connections.clear()
        ssh_connection_locks.clear()
        ssh_connections["host"] = connection

        with patch("safe_ssh_mcp.logger.info") as info:
            self.assertIs(await get_ssh_connection("host"), connection)
            await close_ssh_connections()

        messages = [str(call.args[0]) for call in info.call_args_list]
        self.assertIn("host: connection reused", messages)
        self.assertTrue(
            any("connection pool shutdown complete" in message for message in messages)
        )

    async def test_rejected_pipeline_log_contains_safe_rendering_and_reason(
        self,
    ) -> None:
        pipeline = single("rm", "-rf", "/tmp/test")
        with (
            patch("safe_ssh_mcp.logger.warning") as warning,
            self.assertRaisesRegex(ValueError, "not allowed"),
        ):
            await execute_ssh_command("host", pipeline)

        message = str(warning.call_args.args[0])
        self.assertIn("REJECTED - rm -rf /tmp/test", message)
        self.assertIn("not allowed", message)

    async def test_host_key_rejection_log_has_safe_fingerprint(self) -> None:
        key = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()

        async def reject_host_key(*args: object, **kwargs: object) -> object:
            del args
            factory = cast(
                Callable[[], _PresentedHostKeyObserver],
                kwargs["client_factory"],
            )
            observer = factory()
            observer.validate_host_public_key("host", "192.0.2.1", 22, key)
            raise asyncssh.HostKeyNotVerifiable(
                "Host key is not trusted; credential=do-not-log\nforged-line"
            )

        ssh_connections.clear()
        with (
            patch("safe_ssh_mcp._validate_known_hosts_file"),
            patch("safe_ssh_mcp._windows_agent_path", return_value=None),
            patch("safe_ssh_mcp.asyncssh.connect", side_effect=reject_host_key),
            patch("safe_ssh_mcp.logger.warning") as warning,
            self.assertRaisesRegex(ValueError, "fingerprint SHA256:"),
        ):
            await get_ssh_connection("host")

        message = str(warning.call_args.args[0])
        self.assertIn("type ssh-ed25519", message)
        self.assertNotIn("credential", message)
        self.assertNotIn("forged-line", message)


def main() -> None:
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if isinstance(stream, TextIOWrapper):
            stream.reconfigure(encoding="utf-8")
    unittest.main()


if __name__ == "__main__":
    main()
