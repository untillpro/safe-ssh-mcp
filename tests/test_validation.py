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
"""Regression tests for structured pipeline validation and transport checks."""

import sys
import unittest
from io import TextIOWrapper
from pathlib import Path
from unittest.mock import AsyncMock, patch

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from safe_ssh_mcp import (
    COMMAND_POLICIES,
    MAX_ARGUMENTS_PER_STAGE,
    MAX_PIPELINE_STAGES,
    MAX_POLICY_TOKEN_LENGTH,
    CommandPolicy,
    CommandStage,
    get_ssh_connection,
    initialize_command_policies,
    render_pipeline,
    ssh_connections,
    validate_pipeline,
)

initialize_command_policies(REPOSITORY_ROOT / "policies")


def stage(command: str, *arguments: str) -> CommandStage:
    return {"command": command, "arguments": list(arguments)}


def single(command: str, *arguments: str) -> list[CommandStage]:
    return [stage(command, *arguments)]


TEST_POLICIES: dict[str, CommandPolicy] = {
    "curl": {
        "mode": "whitelist",
        "flags": [
            {"flag": "--disable", "value_pattern": None},
            {"flag": "--get", "value_pattern": None},
            {"flag": "--max-time", "value_pattern": "[1-9][0-9]*"},
        ],
        "require_flags": ["--disable", "--get"],
    },
    "nc": {
        "mode": "whitelist",
        "allows_flag_bundling": True,
        "flags": [
            {"flag": "-z", "value_pattern": None},
            {"flag": "-v", "value_pattern": None},
            {"flag": "-w", "value_pattern": "[1-9][0-9]*"},
            {"flag": "-u", "value_pattern": None},
        ],
        "require_flags": ["-z"],
    },
    "tar": {
        "mode": "whitelist",
        "allows_flag_bundling": True,
        "flags": [
            {"flag": "-t", "value_pattern": None},
            {"flag": "-z", "value_pattern": None},
            {"flag": "-j", "value_pattern": None},
            {"flag": "-v", "value_pattern": None},
        ],
    },
    "probe": {
        "mode": "whitelist",
        "flags": [{"flag": "-0X", "value_pattern": None}],
    },
}


class CommandValidationTests(unittest.TestCase):
    def assert_validation(
        self,
        pipeline: object,
        expected: bool,
        expected_reason: str | None = None,
    ) -> None:
        with patch.dict(COMMAND_POLICIES, TEST_POLICIES, clear=True):
            actual, reason = validate_pipeline(pipeline)
        self.assertEqual(actual, expected, msg=f"{pipeline!r}: {reason}")
        if expected_reason is not None:
            self.assertIn(expected_reason, reason)

    def test_nonletter_short_option_prefixes_are_rejected(self) -> None:
        command_prefixes: dict[str, tuple[str, ...]] = {
            "curl": ("--disable", "--get"),
            "nc": ("-zv",),
            "tar": ("-tv",),
        }
        for command, prefix in command_prefixes.items():
            for flag in ("-0X", "-0o", "-01", "-?x", "-:x"):
                with self.subTest(command=command, flag=flag):
                    self.assert_validation(
                        single(command, *prefix, flag, "example.invalid"),
                        False,
                        f"flag syntax '{flag}' is not allowed",
                    )

    def test_permitted_options_remain_valid(self) -> None:
        pipelines = (
            single(
                "curl",
                "--disable",
                "--get",
                "--max-time",
                "8",
                "https://example.invalid",
            ),
            single("nc", "-zv", "localhost", "22"),
            single("nc", "-z", "-w5", "localhost", "22"),
            single("nc", "-zvw5", "localhost", "22"),
            single("tar", "-tv", "archive.tar.gz"),
            single("tar", "-tz", "archive.tar.gz"),
            single("probe", "-0X"),
        )
        for pipeline in pipelines:
            with self.subTest(pipeline=pipeline):
                self.assert_validation(pipeline, True)

    def test_unlisted_options_are_rejected(self) -> None:
        pipelines = (
            single(
                "curl",
                "--disable",
                "--get",
                "-X",
                "POST",
                "https://example.invalid",
            ),
            single("curl", "--disable", "--get", "-0o", "output.txt"),
            single("nc", "-ze", "localhost", "22"),
            single("tar", "-tx", "archive.tar.gz"),
        )
        for pipeline in pipelines:
            with self.subTest(pipeline=pipeline):
                self.assert_validation(pipeline, False)

    def test_every_pipeline_stage_is_validated(self) -> None:
        self.assert_validation(
            [
                stage("curl", "--disable", "--get", "https://example.invalid"),
                stage("nc", "-zv", "-0X", "localhost", "22"),
            ],
            False,
            "Pipeline stage 2",
        )

    def test_literal_shell_metacharacters_are_safely_quoted(self) -> None:
        pipeline = single(
            "curl",
            "--disable",
            "--get",
            "https://example.invalid/error|warning",
        )
        self.assert_validation(pipeline, True)
        self.assertEqual(
            render_pipeline(pipeline),
            "curl --disable --get 'https://example.invalid/error|warning'",
        )

    def test_pipeline_shape_and_limits_fail_closed(self) -> None:
        cases: tuple[tuple[object, str], ...] = (
            ([], "at least one stage"),
            ({"command": "curl", "arguments": []}, "JSON array"),
            ([{"command": "curl"}], "missing fields"),
            (
                [{"command": "curl", "arguments": [], "extra": True}],
                "unknown fields",
            ),
            ([{"command": "curl", "arguments": "--get"}], "JSON array"),
            ([{"command": "curl", "arguments": [1]}], "must be a string"),
            (single("curl\x00bad"), "NUL"),
            (single("curl", "bad\x00argument"), "NUL"),
            (
                [stage("curl") for _ in range(MAX_PIPELINE_STAGES + 1)],
                "maximum",
            ),
            (
                single(
                    "curl",
                    *("value" for _ in range(MAX_ARGUMENTS_PER_STAGE + 1)),
                ),
                "maximum",
            ),
            (
                single("curl", "x" * (MAX_POLICY_TOKEN_LENGTH + 1)),
                "maximum",
            ),
        )
        for pipeline, reason_fragment in cases:
            with self.subTest(reason=reason_fragment):
                self.assert_validation(pipeline, False, reason_fragment)

    def test_rendered_pipeline_size_is_bounded(self) -> None:
        pipeline = [
            stage(
                "curl",
                *("x" * 40 for _ in range(MAX_ARGUMENTS_PER_STAGE)),
            )
            for _ in range(MAX_PIPELINE_STAGES)
        ]
        self.assert_validation(pipeline, False, "rendered pipeline")


CURL_HANDLER_POLICY: dict[str, CommandPolicy] = {
    "curl": {
        "handler": "curl",
        "require_first": "--disable",
        "single_request": True,
        "targets": [
            {
                "scheme": "https",
                "host": "metrics.internal.example",
                "port": 443,
                "path_prefix": "/api/v1/",
            }
        ],
        "require_flags": ["--disable", "--get"],
        "flags": [
            {"flag": "--disable", "value_pattern": None},
            {"flag": "--get", "value_pattern": None},
            {"flag": "--url", "value_pattern": ".+"},
            {"flag": "--fail", "value_pattern": None},
            {"flag": "--silent", "value_pattern": None},
            {"flag": "--show-error", "value_pattern": None},
            {"flag": "--max-time", "value_pattern": ".+"},
            {"flag": "--connect-timeout", "value_pattern": ".+"},
        ],
    },
}

_ALLOWED = "https://metrics.internal.example/api/v1/"


class CurlHandlerTests(unittest.TestCase):
    def assert_validation(self, pipeline: list[CommandStage], expected: bool) -> None:
        with patch.dict(COMMAND_POLICIES, CURL_HANDLER_POLICY, clear=True):
            actual, reason = validate_pipeline(pipeline)
        self.assertEqual(actual, expected, msg=f"{pipeline!r}: {reason}")

    def test_allowlisted_requests_are_valid(self) -> None:
        pipelines = (
            single("curl", "--disable", "--get", f"{_ALLOWED}status"),
            single(
                "curl",
                "--disable",
                "--get",
                "--fail",
                "--silent",
                "--show-error",
                f"{_ALLOWED}health",
            ),
            single(
                "curl",
                "--disable",
                "--get",
                "--max-time",
                "5",
                "--url",
                f"{_ALLOWED}health",
            ),
            single(
                "curl",
                "--disable",
                "--get",
                "--connect-timeout",
                "2",
                f"--url={_ALLOWED}health",
            ),
        )
        for pipeline in pipelines:
            with self.subTest(pipeline=pipeline):
                self.assert_validation(pipeline, True)

    def test_off_allowlist_targets_are_rejected(self) -> None:
        urls = (
            "https://evil.example/api/v1/x",
            "https://metrics.internal.example/status",
            "https://metrics.internal.example:8443/api/v1/x",
            "http://metrics.internal.example/api/v1/x",
            "file:///etc/passwd",
            "https://user:pw@metrics.internal.example/api/v1/x",
        )
        for url in urls:
            with self.subTest(url=url):
                self.assert_validation(single("curl", "--disable", "--get", url), False)

    def test_structural_constraints_are_enforced(self) -> None:
        pipelines = (
            single("curl", "--get", "--disable", f"{_ALLOWED}x"),
            single("curl", "--disable", f"{_ALLOWED}x"),
            single("curl", "--disable", "--get"),
            single("curl", "--disable", "--get", f"{_ALLOWED}a", f"{_ALLOWED}b"),
            single("curl", "--disable", "--get", f"{_ALLOWED}[1-9]"),
            single("curl", "--disable", "--get", "--max-time", "abc", f"{_ALLOWED}x"),
            single("curl", "--disable", "--get", "--max-time", "0", f"{_ALLOWED}x"),
            single("curl", "--disable", "--get", "--max-time", "-5", f"{_ALLOWED}x"),
            single("curl", "--disable", "--get", "--max-time", "--get", f"{_ALLOWED}x"),
        )
        for pipeline in pipelines:
            with self.subTest(pipeline=pipeline):
                self.assert_validation(pipeline, False)

    def test_unlisted_flags_are_rejected(self) -> None:
        arguments = (
            ("--user", "admin:secret"),
            ("--basic",),
            ("--netrc",),
            ("--data-urlencode", "a=b"),
            ("--netrc-file", "/tmp/n"),
            ("-X", "POST"),
        )
        for extra_arguments in arguments:
            pipeline = single(
                "curl",
                "--disable",
                "--get",
                *extra_arguments,
                f"{_ALLOWED}x",
            )
            with self.subTest(arguments=extra_arguments):
                self.assert_validation(pipeline, False)

    def test_shell_metacharacters_in_an_argument_are_literal(self) -> None:
        pipeline = single("curl", "--disable", "--get", f"{_ALLOWED}$(whoami)")
        self.assert_validation(pipeline, True)
        self.assertIn("'", render_pipeline(pipeline))

    def test_unlisted_command_in_later_stage_is_rejected(self) -> None:
        pipeline = [
            stage("curl", "--disable", "--get", f"{_ALLOWED}x"),
            stage("nc", "-z", "localhost", "22"),
        ]
        self.assert_validation(pipeline, False)


LOOPBACK_USAGE_POLICY: dict[str, CommandPolicy] = {
    "cat": {"mode": "permissive"},
    "jq": {"mode": "permissive"},
    "curl": {
        "handler": "curl",
        "require_first": "--disable",
        "single_request": True,
        "netrc_file_paths": ["/dev/stdin"],
        "targets": [{"host": "loopback"}],
        "require_flags": ["--disable", "--get", "--noproxy"],
        "flags": [
            {"flag": "--disable", "value_pattern": None},
            {"flag": "--get", "value_pattern": None},
            {"flag": "--noproxy", "value_pattern": "\\*"},
            {"flag": "--url", "value_pattern": ".+"},
            {"flag": "--data-urlencode", "value_pattern": ".+"},
            {"flag": "--netrc-file", "value_pattern": "/dev/stdin"},
            {"flag": "--fail", "value_pattern": None},
            {"flag": "--silent", "value_pattern": None},
            {"flag": "--show-error", "value_pattern": None},
            {"flag": "--max-time", "value_pattern": ".+"},
            {"flag": "--connect-timeout", "value_pattern": ".+"},
        ],
    },
}

JQ_NETRC_PROGRAM = r"""
def scalar($key):
  capture("(?m)^[ \t]*" + $key + ":[ \t]*(?<value>[^\r\n]*)").value
  | sub("^[ \t]*"; "") | sub("[ \t]*$"; "")
  | ([39] | implode) as $quote
  | if startswith("\"") and endswith("\"") then
      (try fromjson catch error("Credential parsing failed"))
    elif startswith($quote) and endswith($quote) then
      .[1:-1] | gsub($quote + $quote; $quote)
    else . end;
scalar("username") as $user
| scalar("password") as $password
| "machine 127.0.0.1\nlogin \($user)\npassword \($password)\n"
""".strip()

LOOPBACK_AUTH_PIPELINE: list[CommandStage] = [
    stage("cat", "/etc/example-service/credentials.yaml"),
    stage("jq", "-Rrs", JQ_NETRC_PROGRAM),
    stage(
        "curl",
        "--disable",
        "--get",
        "--noproxy",
        "*",
        "--fail",
        "--silent",
        "--show-error",
        "--max-time",
        "8",
        "--connect-timeout",
        "3",
        "--netrc-file",
        "/dev/stdin",
        "--data-urlencode",
        "check=health",
        "--data-urlencode",
        "time=2026-09-12T14:20:00Z",
        "http://127.0.0.1:8080/health",
    ),
]

_NP_ARGS = ("--disable", "--get", "--noproxy", "*")


class CurlLoopbackUsageTests(unittest.TestCase):
    def assert_validation(self, pipeline: list[CommandStage], expected: bool) -> None:
        with patch.dict(COMMAND_POLICIES, LOOPBACK_USAGE_POLICY, clear=True):
            actual, reason = validate_pipeline(pipeline)
        self.assertEqual(actual, expected, msg=f"{pipeline!r}: {reason}")

    def test_documented_patterns_are_accepted(self) -> None:
        pipelines = (
            LOOPBACK_AUTH_PIPELINE,
            single(
                "curl",
                *_NP_ARGS,
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "8",
                "--data-urlencode",
                "check=readiness",
                "http://127.0.0.1:8080/readiness",
            ),
            single(
                "curl",
                *_NP_ARGS,
                "--max-time",
                "8",
                "http://127.0.0.1:8080/version",
            ),
            single(
                "curl",
                *_NP_ARGS,
                "--max-time",
                "3",
                "--data-urlencode",
                "target=192.0.2.1",
                "http://127.0.0.1:8081/status",
            ),
        )
        for pipeline in pipelines:
            with self.subTest(pipeline=pipeline):
                self.assert_validation(pipeline, True)

    def test_loopback_any_port_path_and_ipv6_are_accepted(self) -> None:
        urls = (
            "http://127.0.0.1:3000/anything/at/all",
            "https://127.0.0.1:9090/api/v1/query",
            "http://[::1]:9090/api/v1/query",
        )
        for url in urls:
            with self.subTest(url=url):
                self.assert_validation(single("curl", *_NP_ARGS, url), True)
        self.assert_validation(
            single(
                "curl",
                *_NP_ARGS,
                "--netrc-file=/dev/stdin",
                "http://127.0.0.1:9090/api/v1/query",
            ),
            True,
        )

    def test_proxy_and_destination_constraints(self) -> None:
        pipelines = (
            single(
                "curl",
                "--disable",
                "--get",
                "http://127.0.0.1:9090/api/v1/query",
            ),
            single(
                "curl",
                "--disable",
                "--get",
                "--noproxy",
                "example.com",
                "http://127.0.0.1:9090/api/v1/query",
            ),
            single("curl", *_NP_ARGS, "http://10.0.0.5:9090/api/v1/query"),
            single(
                "curl",
                *_NP_ARGS,
                "http://169.254.169.254/latest/meta-data/",
            ),
            single("curl", *_NP_ARGS, "http://u:p@127.0.0.1:9090/api/v1/query"),
        )
        for pipeline in pipelines:
            with self.subTest(pipeline=pipeline):
                self.assert_validation(pipeline, False)

    def test_value_constraints_still_block_abuse(self) -> None:
        pipelines = (
            single(
                "curl",
                *_NP_ARGS,
                "--netrc-file",
                "/root/.netrc",
                "http://127.0.0.1:9090/api/v1/query",
            ),
            single(
                "curl",
                *_NP_ARGS,
                "--data-urlencode",
                "query@/etc/passwd",
                "http://127.0.0.1:9090/api/v1/query",
            ),
            single(
                "curl",
                *_NP_ARGS,
                "--data-urlencode",
                "@/etc/passwd",
                "http://127.0.0.1:9090/api/v1/query",
            ),
        )
        for pipeline in pipelines:
            with self.subTest(pipeline=pipeline):
                self.assert_validation(pipeline, False)


class TransportBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_host_with_control_characters_never_connects(self) -> None:
        ssh_connections.clear()
        connect = AsyncMock()
        with (
            patch("safe_ssh_mcp.asyncssh.connect", connect),
            self.assertRaisesRegex(ValueError, "without whitespace or control"),
        ):
            await get_ssh_connection("bad\nhost")
        connect.assert_not_awaited()


def main() -> None:
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if isinstance(stream, TextIOWrapper):
            stream.reconfigure(encoding="utf-8")
    unittest.main()


if __name__ == "__main__":
    main()
