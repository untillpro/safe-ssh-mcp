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
"""Tests for AsyncSSH configuration, host listing, and trust boundaries."""

import asyncio
import base64
import hashlib
import hmac
import sys
import unittest
from io import TextIOWrapper
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from safe_ssh_mcp import (
    DEFAULT_KEEPALIVE_SECONDS,
    KEEPALIVE_COUNT_MAX,
    KNOWN_HOSTS_PATH,
    WINDOWS_OPENSSH_AGENT_PIPE,
    CommandStage,
    _build_connection_options,
    _host_key_failure_message,
    _PresentedHostKeyObserver,
    _split_ssh_config_line,
    _validate_known_hosts_file,
    _validate_ssh_host,
    close_ssh_connections,
    execute_ssh_command,
    get_ssh_connection,
    initialize_command_policies,
    list_ssh_hosts,
    ssh_connection_locks,
    ssh_connections,
)

initialize_command_policies(REPOSITORY_ROOT / "policies")


class HostListingTests(unittest.TestCase):
    def test_windows_path_token_keeps_backslashes(self) -> None:
        tokens = _split_ssh_config_line(
            r"IdentityFile C:\Users\operator\.ssh\id_ed25519",
            Path("config"),
            1,
        )
        self.assertEqual(
            tokens,
            ["IdentityFile", r"C:\Users\operator\.ssh\id_ed25519"],
        )

    def test_concrete_main_config_aliases_are_listed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config"
            config.write_text(
                "Host=direct duplicate wildcard-* !negated user@example bad/name\n"
                "Host final duplicate\n"
                "Match host direct\n",
                encoding="utf-8",
            )

            self.assertEqual(
                list_ssh_hosts(config),
                ["direct", "duplicate", "final"],
            )

    def test_listing_does_not_follow_include_or_evaluate_match(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config"
            config.write_text(
                "Include included.conf\n"
                "Match host direct\n"
                "    User operator\n"
                "Host direct\n",
                encoding="utf-8",
            )
            (root / "included.conf").write_text(
                "Host included\n",
                encoding="utf-8",
            )
            self.assertEqual(list_ssh_hosts(config), ["direct"])

    def test_malformed_line_is_skipped_during_best_effort_listing(self) -> None:
        with TemporaryDirectory() as directory:
            config = Path(directory) / "config"
            config.write_text(
                'Host "unterminated\nHost available\n',
                encoding="utf-8",
            )
            with patch("safe_ssh_mcp.logger.warning") as warning:
                self.assertEqual(list_ssh_hosts(config), ["available"])
            warning.assert_called_once()

    def test_host_validation_is_independent_of_config_listing(self) -> None:
        for host in ("configured-alias", "unlisted.example", "192.0.2.10", "::1"):
            with self.subTest(host=host):
                _validate_ssh_host(host)

        for host in ("", "bad host", "bad\nline", "bad\x00value"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                _validate_ssh_host(host)


class KnownHostsTests(unittest.TestCase):
    @staticmethod
    def _hashed_host(host: str) -> str:
        salt = b"01234567890123456789"
        digest = hmac.new(salt, host.encode("utf-8"), hashlib.sha1).digest()
        return "|1|{}|{}".format(
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        )

    def test_plain_hashed_ca_and_revoked_entries_are_accepted(self) -> None:
        key = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()
        public_key = key.export_public_key().decode("ascii").strip()
        with TemporaryDirectory() as directory:
            known_hosts = Path(directory) / "known_hosts"
            known_hosts.write_text(
                f"plain.example {public_key}\n"
                f"{self._hashed_host('hashed.example')} {public_key}\n"
                f"@cert-authority ca.example {public_key}\n"
                f"@revoked revoked.example {public_key}\n",
                encoding="utf-8",
            )
            with patch("safe_ssh_mcp.KNOWN_HOSTS_PATH", known_hosts):
                _validate_known_hosts_file()

    def test_malformed_known_hosts_fails_without_rewriting_the_file(self) -> None:
        with TemporaryDirectory() as directory:
            known_hosts = Path(directory) / "known_hosts"
            original = "@unsupported host ssh-ed25519 AAAA\n"
            known_hosts.write_text(original, encoding="utf-8")
            with (
                patch("safe_ssh_mcp.KNOWN_HOSTS_PATH", known_hosts),
                self.assertRaisesRegex(ValueError, "malformed or unreadable"),
            ):
                _validate_known_hosts_file()
            self.assertEqual(known_hosts.read_text(encoding="utf-8"), original)

    def test_host_key_error_reports_safe_fingerprint_only(self) -> None:
        observer = _PresentedHostKeyObserver()
        key = asyncssh.generate_private_key("ssh-ed25519").convert_to_public()
        observer.validate_host_public_key("host", "192.0.2.1", 22, key)
        error = asyncssh.HostKeyNotVerifiable(
            "Host key is not trusted; password=do-not-log\nforged-line"
        )
        message = _host_key_failure_message("host", error, observer)
        self.assertIn("type ssh-ed25519", message)
        self.assertIn("fingerprint SHA256:", message)
        self.assertIn("`ssh host`", message)
        self.assertNotIn("password", message)
        self.assertNotIn("forged-line", message)


class AsyncSSHConnectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        ssh_connections.clear()
        ssh_connection_locks.clear()

    def tearDown(self) -> None:
        ssh_connections.clear()
        ssh_connection_locks.clear()

    @staticmethod
    def _connection(closed: bool = False) -> MagicMock:
        connection: MagicMock = MagicMock()
        connection.is_closed.return_value = closed
        connection.get_extra_info.return_value = "operator"
        connection.wait_closed = AsyncMock()
        return connection

    async def test_connection_leaves_config_to_asyncssh_and_uses_known_hosts(
        self,
    ) -> None:
        connection = self._connection()
        connect = AsyncMock(return_value=connection)
        with (
            patch("safe_ssh_mcp._validate_known_hosts_file"),
            patch("safe_ssh_mcp._windows_agent_path", return_value=None),
            patch("safe_ssh_mcp.asyncssh.connect", connect),
        ):
            self.assertIs(await get_ssh_connection("target"), connection)

        connect.assert_awaited_once()
        awaited = connect.await_args
        assert awaited is not None
        args, kwargs = awaited
        self.assertEqual(args, ("target",))
        self.assertNotIn("config", kwargs)
        self.assertIn("options", kwargs)
        self.assertEqual(kwargs["known_hosts"], str(KNOWN_HOSTS_PATH))
        self.assertNotIn("agent_path", kwargs)
        self.assertNotEqual(kwargs["known_hosts"], None)

    async def test_native_windows_agent_pipe_is_explicit(self) -> None:
        connection = self._connection()
        connect = AsyncMock(return_value=connection)
        with (
            patch("safe_ssh_mcp._validate_known_hosts_file"),
            patch(
                "safe_ssh_mcp._windows_agent_path",
                return_value=WINDOWS_OPENSSH_AGENT_PIPE,
            ),
            patch("safe_ssh_mcp.asyncssh.connect", connect),
        ):
            await get_ssh_connection("target")

        awaited = connect.await_args
        assert awaited is not None
        self.assertEqual(
            awaited.kwargs["agent_path"],
            WINDOWS_OPENSSH_AGENT_PIPE,
        )

    async def test_closed_connection_reloads_known_hosts_before_replacement(
        self,
    ) -> None:
        first = self._connection(closed=True)
        second = self._connection()
        ssh_connections["target"] = first
        connect = AsyncMock(return_value=second)
        validate_known_hosts = MagicMock()
        with (
            patch("safe_ssh_mcp._validate_known_hosts_file", validate_known_hosts),
            patch("safe_ssh_mcp._windows_agent_path", return_value=None),
            patch("safe_ssh_mcp.asyncssh.connect", connect),
        ):
            self.assertIs(await get_ssh_connection("target"), second)

        validate_known_hosts.assert_called_once()
        connect.assert_awaited_once()
        first.close.assert_called_once()
        first.wait_closed.assert_awaited_once()

    async def test_concurrent_connection_creation_uses_one_connection(self) -> None:
        connection = self._connection()
        connect_started = asyncio.Event()
        allow_connect = asyncio.Event()

        async def connect_once(*args: object, **kwargs: object) -> MagicMock:
            del args, kwargs
            connect_started.set()
            await allow_connect.wait()
            return connection

        connect = AsyncMock(side_effect=connect_once)
        with (
            patch("safe_ssh_mcp._validate_known_hosts_file"),
            patch("safe_ssh_mcp._windows_agent_path", return_value=None),
            patch("safe_ssh_mcp.asyncssh.connect", connect),
        ):
            first = asyncio.create_task(get_ssh_connection("target"))
            second = asyncio.create_task(get_ssh_connection("target"))
            await connect_started.wait()
            allow_connect.set()
            first_result, second_result = await asyncio.gather(first, second)

        self.assertIs(first_result, connection)
        self.assertIs(second_result, connection)
        connect.assert_awaited_once()

    async def test_healthy_connection_is_reused(self) -> None:
        connection = self._connection()
        ssh_connections["target"] = connection
        connect = AsyncMock()
        with patch("safe_ssh_mcp.asyncssh.connect", connect):
            self.assertIs(await get_ssh_connection("target"), connection)
            self.assertIs(await get_ssh_connection("target"), connection)
        connect.assert_not_awaited()

    async def test_unlisted_host_is_passed_to_asyncssh(self) -> None:
        connection = self._connection()
        connect = AsyncMock(return_value=connection)
        with (
            patch("safe_ssh_mcp._validate_known_hosts_file"),
            patch("safe_ssh_mcp._windows_agent_path", return_value=None),
            patch("safe_ssh_mcp.asyncssh.connect", connect),
        ):
            self.assertIs(await get_ssh_connection("unlisted.example"), connection)

        connect.assert_awaited_once()
        awaited = connect.await_args
        assert awaited is not None
        self.assertEqual(awaited.args, ("unlisted.example",))

    async def test_authentication_failure_is_not_retried(self) -> None:
        connect = AsyncMock(side_effect=asyncssh.PermissionDenied("denied"))
        with (
            patch("safe_ssh_mcp._validate_known_hosts_file"),
            patch("safe_ssh_mcp._windows_agent_path", return_value=None),
            patch("safe_ssh_mcp.asyncssh.connect", connect),
            self.assertRaisesRegex(ValueError, "authentication failed"),
        ):
            await get_ssh_connection("target")
        connect.assert_awaited_once()

    def test_keepalive_defaults_are_bounded(self) -> None:
        base: MagicMock = MagicMock()
        base.config.get.return_value = None
        base.keepalive_interval = 0
        configured: MagicMock = MagicMock()
        options_type = MagicMock(side_effect=[base, configured])

        with patch(
            "safe_ssh_mcp.asyncssh.SSHClientConnectionOptions",
            options_type,
        ):
            self.assertIs(_build_connection_options("target"), configured)

        second_call = options_type.call_args_list[1]
        self.assertEqual(
            second_call.kwargs["keepalive_interval"],
            DEFAULT_KEEPALIVE_SECONDS,
        )
        self.assertEqual(
            second_call.kwargs["keepalive_count_max"],
            KEEPALIVE_COUNT_MAX,
        )

    def test_configured_keepalive_interval_is_preserved(self) -> None:
        base: MagicMock = MagicMock()
        base.config.get.return_value = 9
        base.keepalive_interval = 9
        configured: MagicMock = MagicMock()
        options_type = MagicMock(side_effect=[base, configured])

        with patch(
            "safe_ssh_mcp.asyncssh.SSHClientConnectionOptions",
            options_type,
        ):
            self.assertIs(_build_connection_options("target"), configured)

        second_call = options_type.call_args_list[1]
        self.assertEqual(second_call.kwargs["keepalive_interval"], 9)
        self.assertEqual(
            second_call.kwargs["keepalive_count_max"],
            KEEPALIVE_COUNT_MAX,
        )

    async def test_command_transport_failure_evicts_without_retry(self) -> None:
        connection = self._connection(closed=True)
        connection.create_process = AsyncMock(
            side_effect=asyncssh.ConnectionLost("connection lost")
        )
        ssh_connections["target"] = connection
        pipeline: list[CommandStage] = [{"command": "uptime", "arguments": []}]

        with (
            patch("safe_ssh_mcp.get_ssh_connection", return_value=connection),
            self.assertRaisesRegex(ConnectionError, "ConnectionLost"),
        ):
            await execute_ssh_command("target", pipeline)

        connection.create_process.assert_awaited_once()
        self.assertNotIn("target", ssh_connections)
        connection.close.assert_called_once()
        connection.wait_closed.assert_awaited_once()

    async def test_timeout_evicts_connection_only_when_closed(self) -> None:
        connection = self._connection(closed=True)
        ssh_connections["target"] = connection
        pipeline: list[CommandStage] = [{"command": "uptime", "arguments": []}]

        with (
            patch("safe_ssh_mcp.get_ssh_connection", return_value=connection),
            patch(
                "safe_ssh_mcp._run_bounded_process",
                new=AsyncMock(side_effect=TimeoutError("deadline")),
            ),
            self.assertRaisesRegex(TimeoutError, "timed out"),
        ):
            await execute_ssh_command("target", pipeline)

        self.assertNotIn("target", ssh_connections)
        connection.close.assert_called_once()
        connection.wait_closed.assert_awaited_once()

    async def test_cancellation_retains_usable_connection(self) -> None:
        connection = self._connection()
        ssh_connections["target"] = connection
        pipeline: list[CommandStage] = [{"command": "uptime", "arguments": []}]

        with (
            patch("safe_ssh_mcp.get_ssh_connection", return_value=connection),
            patch(
                "safe_ssh_mcp._run_bounded_process",
                new=AsyncMock(side_effect=asyncio.CancelledError()),
            ),
            self.assertRaises(asyncio.CancelledError),
        ):
            await execute_ssh_command("target", pipeline)

        self.assertIs(ssh_connections["target"], connection)
        connection.close.assert_not_called()

    async def test_pool_shutdown_is_complete_and_idempotent(self) -> None:
        first = self._connection()
        second = self._connection()
        ssh_connections.update({"first": first, "second": second})
        ssh_connection_locks.update({"first": asyncio.Lock(), "second": asyncio.Lock()})

        await close_ssh_connections()
        await close_ssh_connections()

        self.assertEqual(ssh_connections, {})
        self.assertEqual(ssh_connection_locks, {})
        first.close.assert_called_once()
        second.close.assert_called_once()
        first.wait_closed.assert_awaited_once()
        second.wait_closed.assert_awaited_once()

    def test_asyncssh_applies_connection_and_proxy_configuration(self) -> None:
        with TemporaryDirectory() as directory:
            private_key = asyncssh.generate_private_key("ssh-ed25519")
            identity_file = Path(directory) / "identity"
            identity_file.write_bytes(private_key.export_private_key())
            config = Path(directory) / "config"
            config.write_text(
                "Host target\n"
                "    HostName 192.0.2.10\n"
                "    User operator\n"
                "    Port 2200\n"
                f"    IdentityFile {identity_file.as_posix()}\n"
                "    ProxyJump bastion\n"
                "    ConnectTimeout 7\n"
                "    ServerAliveInterval 9\n",
                encoding="utf-8",
            )
            options = asyncssh.SSHClientConnectionOptions(
                host="target",
                config=str(config),
            )
            self.assertEqual(options.host, "192.0.2.10")
            self.assertEqual(options.username, "operator")
            self.assertEqual(options.port, 2200)
            self.assertEqual(options.tunnel, "bastion")
            self.assertEqual(options.connect_timeout, 7)
            self.assertEqual(options.keepalive_interval, 9)
            assert options.client_keys is not None
            self.assertEqual(len(options.client_keys), 1)

    def test_asyncssh_applies_included_configuration(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            included = root / "included.conf"
            included.write_text(
                "Host target\n"
                "    HostName 192.0.2.10\n"
                "    User operator\n"
                "    Port 2200\n",
                encoding="utf-8",
            )
            config = root / "config"
            config.write_text(
                f"Include {included.as_posix()}\n",
                encoding="utf-8",
            )

            options = asyncssh.SSHClientConnectionOptions(
                host="target",
                config=str(config),
            )

            self.assertEqual(options.host, "192.0.2.10")
            self.assertEqual(options.username, "operator")
            self.assertEqual(options.port, 2200)


def main() -> None:
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if isinstance(stream, TextIOWrapper):
            stream.reconfigure(encoding="utf-8")
    unittest.main()


if __name__ == "__main__":
    main()
