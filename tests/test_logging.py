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

import sys
import unittest
from collections.abc import Callable
from io import TextIOWrapper
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from safe_ssh_mcp import (
    CommandStage,
    _PresentedHostKeyObserver,
    close_ssh_connections,
    execute_ssh_command,
    get_ssh_connection,
    initialize_command_policies,
    render_pipeline,
    ssh_connection_locks,
    ssh_connections,
    validate_pipeline,
)

initialize_command_policies(REPOSITORY_ROOT / "policies")


def single(command: str, *arguments: str) -> list[CommandStage]:
    return [{"command": command, "arguments": list(arguments)}]


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
