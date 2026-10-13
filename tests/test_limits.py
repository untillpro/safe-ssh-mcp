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
"""Tests for bounded command streams, response limits, and cleanup."""

import asyncio
import sys
from collections.abc import Coroutine
from pathlib import Path
from typing import Any, TypeVar, cast
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from safe_ssh_mcp import (
    COMMAND_TIMEOUT_SECONDS,
    MAX_RESPONSE_BYTES,
    CommandStage,
    _run_bounded_process,
    execute_ssh_command,
    initialize_command_policies,
)

initialize_command_policies(REPOSITORY_ROOT / "policies")


class _FakeProcess:
    """Minimal AsyncSSH process double with independently readable streams."""

    def __init__(
        self,
        stdout: bytes = b"ok",
        stderr: bytes = b"",
        exit_status: int = 0,
        *,
        block: bool = False,
    ) -> None:
        self._closed = asyncio.Event()
        self._eof_streams = 0
        self.close_calls = 0
        self.exit_status = exit_status
        self.stdout_reader = _FakeReader(stdout, self, block=block)
        self.stderr_reader = _FakeReader(stderr, self, block=block)
        self.stdout = cast(asyncssh.SSHReader[bytes], self.stdout_reader)
        self.stderr = cast(asyncssh.SSHReader[bytes], self.stderr_reader)

    def stream_finished(self) -> None:
        self._eof_streams += 1
        if self._eof_streams == 2:
            self._closed.set()

    def close(self) -> None:
        self.close_calls += 1
        self._closed.set()

    async def wait_closed(self) -> None:
        await self._closed.wait()


class _FakeReader:
    def __init__(
        self,
        data: bytes,
        process: _FakeProcess,
        *,
        block: bool,
    ) -> None:
        self._data = data
        self._process = process
        self._block = block
        self._position = 0
        self._reported_eof = False
        self.started = asyncio.Event()
        self.max_requested_bytes = 0

    @property
    def bytes_served(self) -> int:
        return self._position

    async def read(self, size: int) -> bytes:
        self.started.set()
        self.max_requested_bytes = max(self.max_requested_bytes, size)
        await asyncio.sleep(0)
        if self._block:
            await self._process._closed.wait()
            return b""
        if self._position < len(self._data):
            end = min(self._position + size, len(self._data))
            chunk = self._data[self._position : end]
            self._position = end
            return chunk
        if not self._reported_eof:
            self._reported_eof = True
            self._process.stream_finished()
        return b""


T = TypeVar("T")


def run(coroutine: Coroutine[Any, Any, T]) -> T:
    """Run one async test operation in a fresh event loop."""
    return asyncio.run(coroutine)


def make_ssh_mocks(
    stdout_data: bytes = b"ok",
    stderr_data: bytes = b"",
    exit_code: int = 0,
    *,
    block: bool = False,
) -> tuple[MagicMock, _FakeProcess]:
    """Create a mock SSH client with a streaming process double."""
    process = _FakeProcess(
        stdout_data,
        stderr_data,
        exit_code,
        block=block,
    )
    client: MagicMock = MagicMock()
    client.get_extra_info.return_value = "test"
    client.is_closed.return_value = False
    client.create_process = AsyncMock(
        return_value=cast(asyncssh.SSHClientProcess[bytes], process)
    )
    return client, process


PIPELINE: list[CommandStage] = [{"command": "ls", "arguments": []}]


def test_execute_stdout_truncated() -> None:
    """More than 2 MiB of stdout is stopped without buffering it all."""
    big_data = b"x" * (2 * 1024 * 1024 + 1)
    client, process = make_ssh_mocks(stdout_data=big_data)

    with (
        patch("safe_ssh_mcp._validate_normalized_pipeline", return_value=(True, "OK")),
        patch("safe_ssh_mcp.get_ssh_connection", return_value=client),
    ):
        stdout_text, _stderr_text, code = run(execute_ssh_command("host", PIPELINE))

    assert stdout_text.startswith("x" * 100)
    assert f"exceeded {MAX_RESPONSE_BYTES // 1024}KB limit" in stdout_text
    assert code is None
    assert process.close_calls >= 1
    assert process.stdout_reader.bytes_served <= MAX_RESPONSE_BYTES + 1
    assert process.stdout_reader.max_requested_bytes <= MAX_RESPONSE_BYTES + 1
    print("[PASS] test_execute_stdout_truncated")


def test_execute_small_output_not_truncated() -> None:
    """Small output and the remote exit status are returned unchanged."""
    client, process = make_ssh_mocks(stdout_data=b"hello world", exit_code=7)

    with (
        patch("safe_ssh_mcp._validate_normalized_pipeline", return_value=(True, "OK")),
        patch("safe_ssh_mcp.get_ssh_connection", return_value=client),
    ):
        stdout_text, _stderr_text, code = run(execute_ssh_command("host", PIPELINE))

    assert stdout_text == "hello world"
    assert "[truncated" not in stdout_text
    assert code == 7
    assert process.close_calls == 0
    print("[PASS] test_execute_small_output_not_truncated")


def test_execute_stderr_truncated() -> None:
    """stderr uses its own limit and makes the exit status unavailable."""
    big_err = b"e" * (MAX_RESPONSE_BYTES + 50)
    client, process = make_ssh_mocks(stderr_data=big_err)

    with (
        patch("safe_ssh_mcp._validate_normalized_pipeline", return_value=(True, "OK")),
        patch("safe_ssh_mcp.get_ssh_connection", return_value=client),
    ):
        _stdout_text, stderr_text, code = run(execute_ssh_command("host", PIPELINE))

    assert "[truncated" in stderr_text
    assert code is None
    assert process.stderr_reader.bytes_served <= MAX_RESPONSE_BYTES + 1
    print("[PASS] test_execute_stderr_truncated")


def test_execute_renders_pipeline_and_returns_remote_exit_status() -> None:
    """The process receives bytes mode and the final remote exit status is kept."""
    client, _ = make_ssh_mocks(exit_code=7)
    pipeline: list[CommandStage] = [
        {"command": "ls", "arguments": ["-la"]},
        {"command": "grep", "arguments": ["error|warning"]},
    ]

    with (
        patch("safe_ssh_mcp._validate_normalized_pipeline", return_value=(True, "OK")),
        patch("safe_ssh_mcp.get_ssh_connection", return_value=client),
    ):
        _, _, code = run(execute_ssh_command("host", pipeline))

    client.create_process.assert_awaited_once_with(
        "ls -la | grep 'error|warning'",
        encoding=None,
        stdin=asyncssh.DEVNULL,
    )
    assert code == 7
    print("[PASS] test_execute_renders_pipeline_and_returns_remote_exit_status")


def test_stdout_and_stderr_are_consumed_concurrently() -> None:
    """Both streams begin reading before a full SSH window can block either one."""
    client, process = make_ssh_mocks(
        stdout_data=b"o" * (2 * 1024 * 1024),
        stderr_data=b"e" * (2 * 1024 * 1024),
    )

    run(
        _run_bounded_process(
            cast(asyncssh.SSHClientConnection, client),
            "large-output",
        )
    )

    assert process.stdout_reader.started.is_set()
    assert process.stderr_reader.started.is_set()
    assert process.stdout_reader.bytes_served <= MAX_RESPONSE_BYTES + 1
    assert process.stderr_reader.bytes_served <= MAX_RESPONSE_BYTES + 1
    print("[PASS] test_stdout_and_stderr_are_consumed_concurrently")


def test_split_utf8_sequence_is_decoded_safely() -> None:
    """Truncation through a multibyte code point uses replacement decoding."""
    split_utf8 = b"x" * (MAX_RESPONSE_BYTES - 1) + b"\xe2\x82\xac"
    client, _ = make_ssh_mocks(stdout_data=split_utf8)

    with (
        patch("safe_ssh_mcp._validate_normalized_pipeline", return_value=(True, "OK")),
        patch("safe_ssh_mcp.get_ssh_connection", return_value=client),
    ):
        stdout_text, _stderr_text, code = run(execute_ssh_command("host", PIPELINE))

    assert "�" in stdout_text
    assert "[truncated" in stdout_text
    assert code is None
    print("[PASS] test_split_utf8_sequence_is_decoded_safely")


def test_execute_timeout_closes_remote_process() -> None:
    """The total command deadline closes a process whose streams never finish."""
    client, process = make_ssh_mocks(block=True)

    with (
        patch("safe_ssh_mcp._validate_normalized_pipeline", return_value=(True, "OK")),
        patch("safe_ssh_mcp.get_ssh_connection", return_value=client),
        patch("safe_ssh_mcp.COMMAND_TIMEOUT_SECONDS", 0.05),
    ):
        try:
            run(execute_ssh_command("host", PIPELINE))
            assert False, "Should have raised TimeoutError"
        except TimeoutError as error:
            assert "timed out" in str(error)

    assert process.close_calls >= 1
    print("[PASS] test_execute_timeout_closes_remote_process")


def test_cancellation_closes_remote_process() -> None:
    """Caller cancellation closes the remote process before propagating."""

    async def cancel_execution() -> _FakeProcess:
        client, process = make_ssh_mocks(block=True)
        with (
            patch(
                "safe_ssh_mcp._validate_normalized_pipeline",
                return_value=(True, "OK"),
            ),
            patch("safe_ssh_mcp.get_ssh_connection", return_value=client),
        ):
            task = asyncio.create_task(execute_ssh_command("host", PIPELINE))
            await process.stdout_reader.started.wait()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            else:
                raise AssertionError("Cancellation was not propagated")
        return process

    process = run(cancel_execution())
    assert process.close_calls >= 1
    print("[PASS] test_cancellation_closes_remote_process")


if __name__ == "__main__":
    print(
        f"\nLimits: response={MAX_RESPONSE_BYTES // 1024}KB, "
        f"timeout={COMMAND_TIMEOUT_SECONDS}s\n"
    )

    test_execute_stdout_truncated()
    test_execute_small_output_not_truncated()
    test_execute_stderr_truncated()
    test_execute_renders_pipeline_and_returns_remote_exit_status()
    test_stdout_and_stderr_are_consumed_concurrently()
    test_split_utf8_sequence_is_decoded_safely()
    test_execute_timeout_closes_remote_process()
    test_cancellation_closes_remote_process()

    print("\n" + "=" * 60)
    print("ALL LIMIT TESTS PASSED")
    print("=" * 60)
