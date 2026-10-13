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
"""Regression tests for the structured command-policy DSL."""

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import ClassVar, cast
from unittest.mock import patch

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from safe_ssh_mcp import (
    COMMAND_POLICIES,
    MAX_PATTERN_LENGTH,
    MAX_POLICY_TOKEN_LENGTH,
    CommandPolicy,
    CommandStage,
    _normalize_command_policy,
    execute_ssh_command,
    initialize_command_policies,
    load_command_policies,
    render_pipeline,
    ssh_describe_validation_rules,
    ssh_list_allowed_commands,
    ssh_validate_command,
    validate_pipeline,
)

initialize_command_policies(REPOSITORY_ROOT / "policies")


def policy(command: str, raw_config: object) -> CommandPolicy:
    return _normalize_command_policy(command, raw_config, "test policy")


def single(command: str, *arguments: str) -> list[CommandStage]:
    return [{"command": command, "arguments": list(arguments)}]


class PolicyLoadingTests(unittest.TestCase):
    @staticmethod
    def write_policy(directory: Path, name: str, content: str) -> None:
        (directory / name).write_text(content, encoding="utf-8")

    def test_yaml_is_the_sole_policy_source(self) -> None:
        with TemporaryDirectory() as temp_dir:
            policy_dir = Path(temp_dir)
            self.write_policy(policy_dir, "only.yaml", "probe:\n  mode: permissive\n")
            loaded = load_command_policies(policy_dir)
        self.assertEqual(set(loaded), {"probe"})

    def test_missing_or_empty_policy_directory_fails_startup(self) -> None:
        with TemporaryDirectory() as temp_dir:
            policy_dir = Path(temp_dir)
            with self.assertRaisesRegex(FileNotFoundError, "No YAML policy files"):
                load_command_policies(policy_dir)
            with self.assertRaisesRegex(
                FileNotFoundError, "Policy directory not found"
            ):
                load_command_policies(policy_dir / "missing")

    def test_malformed_policy_file_fails_startup(self) -> None:
        with TemporaryDirectory() as temp_dir:
            policy_dir = Path(temp_dir)
            self.write_policy(policy_dir, "broken.yaml", "probe: [\n")
            with self.assertRaisesRegex(ValueError, "Failed to parse broken.yaml"):
                load_command_policies(policy_dir)

    def test_duplicate_command_across_files_fails_startup(self) -> None:
        with TemporaryDirectory() as temp_dir:
            policy_dir = Path(temp_dir)
            content = "probe:\n  mode: permissive\n"
            self.write_policy(policy_dir, "first.yaml", content)
            self.write_policy(policy_dir, "second.yaml", content)
            with self.assertRaisesRegex(
                ValueError,
                "Duplicate policy for command 'probe'.*already defined in first.yaml",
            ):
                load_command_policies(policy_dir)

    def test_duplicate_yaml_key_fails_startup(self) -> None:
        with TemporaryDirectory() as temp_dir:
            policy_dir = Path(temp_dir)
            self.write_policy(
                policy_dir,
                "duplicate.yaml",
                "probe:\n  mode: permissive\nprobe:\n  mode: whitelist\n",
            )
            with self.assertRaisesRegex(ValueError, "Duplicate YAML key 'probe'"):
                load_command_policies(policy_dir)


class ShippedPolicyRegressionTests(unittest.TestCase):
    def assert_validation(
        self,
        pipeline: list[CommandStage],
        expected: bool,
        reason_fragment: str | None = None,
    ) -> None:
        actual, reason = validate_pipeline(pipeline)
        self.assertEqual(actual, expected, msg=f"{pipeline!r}: {reason}")
        if reason_fragment is not None:
            self.assertIn(reason_fragment, reason)

    def test_modifying_commands_are_rejected(self) -> None:
        for pipeline in (
            single("systemctl", "restart", "nginx"),
            single("docker", "rm", "web"),
            single("docker", "exec", "web", "rm", "/tmp/file"),
            single("find", ".", "-fprint", "output.txt"),
            single("journalctl", "--vacuum-size=1M"),
            single("journalctl", "--sync"),
            single("sort", "--output=file"),
            single("sort", "-ofile"),
            single("sort", "-rofile", "input.txt"),
            single("sort", "--compress-program=sh", "input.txt"),
            single("date", "--set=now"),
            single("date", "-usnow"),
            single("yq", "-i=xml", ".value", "data.yaml"),
            single("yq", "-vi", ".value", "data.yaml"),
            single("hostname", "changed-hostname"),
            single("ss", "-K", "dst", "192.0.2.1"),
        ):
            with self.subTest(pipeline=pipeline):
                self.assert_validation(pipeline, False, "not executed")

    def test_intended_read_only_commands_are_accepted(self) -> None:
        for pipeline in (
            single("systemctl", "status", "nginx"),
            single("docker", "ps"),
            single("docker", "exec", "example", "uptime"),
            single("journalctl", "-n", "100"),
            single("sort", "file"),
            single("date"),
            single("hostname"),
            single("ss", "-ltn"),
        ):
            with self.subTest(pipeline=pipeline):
                self.assert_validation(pipeline, True)

    def test_representative_prompt_forms_are_accepted(self) -> None:
        pipelines: tuple[list[CommandStage], ...] = (
            single("grep", "-c", "^processor", "/proc/cpuinfo"),
            [
                {"command": "du", "arguments": ["-ah", "/var/log"]},
                {"command": "sort", "arguments": ["-hr"]},
                {"command": "head", "arguments": ["-n", "30"]},
            ],
            single(
                "ps",
                "-eo",
                "pid,ppid,user,stat,etimes,pcpu,pmem,comm",
                "--sort=-pcpu",
            ),
            single("systemctl", "status", "systemd-journald"),
            single("journalctl", "-p", "warning", "-n", "200", "--no-pager"),
            single(
                "find",
                "/var/log",
                "-maxdepth",
                "2",
                "-type",
                "f",
                "-size",
                "+100M",
                "-printf",
                "%s %p\\n",
            ),
            single("ss", "-lntup"),
            single("getent", "passwd", "0"),
            single("last", "-n", "20"),
            single(
                "stat",
                "/etc/passwd",
                "/etc/shadow",
                "/etc/group",
                "/etc/gshadow",
            ),
            single("ls", "-ld", "/var/log", "/etc/logrotate.d"),
        )
        for pipeline in pipelines:
            with self.subTest(pipeline=pipeline):
                self.assert_validation(pipeline, True)


class DockerHandlerTests(unittest.TestCase):
    DOCKER_RAW_POLICY: ClassVar[dict[str, object]] = {
        "handler": "docker",
        "mode": "whitelist",
        "positional_variants": [
            ["(?:ps|images|version)"],
            {
                "args": ["(?:inspect|logs)"],
                "rest_pattern": "[A-Za-z0-9_.:@/-]{1,256}",
                "min_rest": 1,
                "max_rest": 10,
            },
            {
                "args": ["stats"],
                "rest_pattern": "[A-Za-z0-9_.:@/-]{1,256}",
                "min_rest": 0,
                "max_rest": 10,
            },
        ],
    }
    DOCKER_POLICY = policy("docker", DOCKER_RAW_POLICY)
    NODETOOL_POLICY = policy(
        "nodetool",
        {
            "mode": "whitelist",
            "positional_variants": [["(?:status|info)"]],
        },
    )
    CURL_POLICY = policy(
        "curl",
        {
            "handler": "curl",
            "require_first": "--disable",
            "single_request": True,
            "targets": [{"host": "loopback"}],
            "require_flags": ["--disable", "--get", "--noproxy"],
            "flags": [
                {"flag": "--disable", "value_pattern": None},
                {"flag": "--get", "value_pattern": None},
                {"flag": "--noproxy", "value_pattern": "\\*"},
            ],
        },
    )
    POLICIES: ClassVar[dict[str, CommandPolicy]] = {
        "docker": DOCKER_POLICY,
        "nodetool": NODETOOL_POLICY,
        "uptime": policy("uptime", {"mode": "permissive"}),
        "grep": policy("grep", {"mode": "permissive"}),
        "curl": CURL_POLICY,
    }

    def assert_docker(
        self,
        expected: bool,
        *arguments: str,
        reason_fragment: str | None = None,
    ) -> None:
        with patch.dict(COMMAND_POLICIES, self.POLICIES, clear=True):
            accepted, reason = validate_pipeline(single("docker", *arguments))
        self.assertEqual(accepted, expected, msg=reason)
        if reason_fragment is not None:
            self.assertIn(reason_fragment, reason)

    def test_existing_inspection_rules_are_preserved(self) -> None:
        self.assert_docker(True, "ps")
        self.assert_docker(True, "inspect", "service.container-1")
        self.assert_docker(False, "rm", "service.container-1")

    def test_inspection_requirements_do_not_apply_to_exec_envelope(self) -> None:
        docker_policy = policy(
            "docker",
            {
                "handler": "docker",
                "mode": "whitelist",
                "flags": [{"flag": "--format", "value_pattern": ".+"}],
                "require_flags": ["--format"],
                "positional_variants": [["ps"]],
            },
        )
        policies = dict(self.POLICIES)
        policies["docker"] = docker_policy
        with patch.dict(COMMAND_POLICIES, policies, clear=True):
            inspection_accepted, _ = validate_pipeline(single("docker", "ps"))
            exec_accepted, exec_reason = validate_pipeline(
                single("docker", "exec", "service", "uptime")
            )
        self.assertFalse(inspection_accepted)
        self.assertTrue(exec_accepted, msg=exec_reason)

    def test_exec_accepts_policy_validated_inner_commands(self) -> None:
        for container in (
            "scylla",
            "example-db-service.1",
            "4d3c2b1a",
            "/scylla",
            "a",
        ):
            with self.subTest(container=container):
                self.assert_docker(True, "exec", container, "nodetool", "status")

        self.assert_docker(True, "exec", "scylla", "uptime")

    def test_exec_delegates_to_other_specialized_handlers(self) -> None:
        self.assert_docker(
            True,
            "exec",
            "service",
            "curl",
            "--disable",
            "--get",
            "--noproxy",
            "*",
            "http://127.0.0.1:8080/health",
        )

    def test_exec_rejects_inner_policy_violations(self) -> None:
        self.assert_docker(
            False,
            "exec",
            "scylla",
            "nodetool",
            "reloadschema",
            reason_fragment="inner command 'nodetool' failed policy validation",
        )
        self.assert_docker(
            False,
            "exec",
            "scylla",
            "sh",
            "-c",
            "id",
            reason_fragment="Command 'sh'",
        )

    def test_exec_rejects_options_and_missing_tokens(self) -> None:
        cases: tuple[tuple[tuple[str, ...], str], ...] = (
            (("exec", "-it", "scylla", "uptime"), "options are not allowed"),
            (("exec", "", "uptime"), "requires a non-empty container"),
            (("exec",), "requires a container"),
            (("exec", "scylla"), "requires an inner command"),
        )
        for arguments, fragment in cases:
            with self.subTest(arguments=arguments):
                self.assert_docker(
                    False,
                    *arguments,
                    reason_fragment=fragment,
                )

    def test_exec_rejects_nested_docker_handler_invocation(self) -> None:
        self.assert_docker(
            False,
            "exec",
            "outer",
            "docker",
            "exec",
            "inner",
            "uptime",
            reason_fragment="nested Docker handler invocation",
        )

    def test_container_and_inner_arguments_remain_literal_when_rendered(self) -> None:
        pipeline = single(
            "docker",
            "exec",
            "service;id",
            "grep",
            "error|warning",
            "/var/log/app log",
        )
        with patch.dict(COMMAND_POLICIES, self.POLICIES, clear=True):
            accepted, reason = validate_pipeline(pipeline)
        self.assertTrue(accepted, msg=reason)
        self.assertEqual(
            render_pipeline(pipeline),
            "docker exec 'service;id' grep 'error|warning' '/var/log/app log'",
        )

    def test_removing_handler_preserves_inspection_and_disables_exec(self) -> None:
        raw_policy = dict(self.DOCKER_RAW_POLICY)
        del raw_policy["handler"]
        inspection_only = policy("docker", raw_policy)
        policies = dict(self.POLICIES)
        policies["docker"] = inspection_only
        with patch.dict(COMMAND_POLICIES, policies, clear=True):
            inspection_accepted, inspection_reason = validate_pipeline(
                single("docker", "ps")
            )
            exec_accepted, _ = validate_pipeline(
                single("docker", "exec", "service", "uptime")
            )
        self.assertTrue(inspection_accepted, msg=inspection_reason)
        self.assertFalse(exec_accepted)


class SecurityPolicyRegressionTests(unittest.TestCase):
    def assert_security_command(
        self, expected: bool, command: str, *arguments: str
    ) -> None:
        accepted, reason = validate_pipeline(single(command, *arguments))
        self.assertEqual(accepted, expected, msg=f"{command} {arguments!r}: {reason}")

    def test_exact_read_only_security_forms_are_accepted(self) -> None:
        cases = (
            ("ufw", "status"),
            ("ufw", "status", "verbose"),
            ("ufw", "status", "numbered"),
            ("nft", "list", "ruleset"),
            ("iptables", "-L"),
            ("iptables", "-L", "-n", "-v"),
            ("iptables", "-Lnv"),
            ("iptables", "-t", "nat", "-L", "PREROUTING", "-n"),
            ("ip6tables", "-L", "INPUT", "-n", "-v", "-x"),
            ("getenforce",),
            ("aa-status",),
            ("auditctl", "-s"),
            ("fail2ban-client", "status"),
            ("fail2ban-client", "status", "sshd"),
        )
        for command, *arguments in cases:
            with self.subTest(command=command, arguments=arguments):
                self.assert_security_command(True, command, *arguments)

    def test_modifying_or_unrestricted_security_forms_are_rejected(self) -> None:
        cases = (
            ("ufw", "enable"),
            ("ufw", "delete", "allow", "22"),
            ("ufw", "status", "verbose", "extra"),
            ("nft", "flush", "ruleset"),
            ("nft", "add", "table", "inet", "filter"),
            ("nft", "list", "table", "filter"),
            ("iptables", "-F"),
            ("iptables", "-A", "INPUT", "-j", "ACCEPT"),
            ("iptables", "-L", "-j", "ACCEPT"),
            ("iptables", "-t", "custom", "-L"),
            ("iptables", "-L", "INPUT", "extra"),
            ("iptables", "-L", "--", "-F"),
            ("ip6tables", "-P", "INPUT", "DROP"),
            ("getenforce", "extra"),
            ("aa-status", "--enabled"),
            ("auditctl", "-e", "0"),
            ("auditctl", "-s", "-e", "0"),
            ("fail2ban-client", "set", "sshd", "banip", "192.0.2.1"),
            ("fail2ban-client", "status", "sshd", "extra"),
            ("fail2ban-client", "--", "status", "-evil"),
        )
        for command, *arguments in cases:
            with self.subTest(command=command, arguments=arguments):
                self.assert_security_command(False, command, *arguments)


class PositionalVariantTests(unittest.TestCase):
    ROUTER_POLICY = policy(
        "router",
        {
            "mode": "whitelist",
            "positional_variants": [
                [],
                ["network", "(?:inspect|ls)", "(?:status|is-active|is-enabled)"],
                {
                    "args": ["somecmd"],
                    "rest_pattern": "[A-Za-z0-9_.-]+",
                    "min_rest": 1,
                    "max_rest": 2,
                },
            ],
        },
    )

    def assert_router(self, arguments: list[str], expected: bool) -> None:
        with patch.dict(COMMAND_POLICIES, {"router": self.ROUTER_POLICY}, clear=True):
            actual, reason = validate_pipeline(single("router", *arguments))
        self.assertEqual(actual, expected, msg=reason)

    def test_exact_empty_and_multi_level_variants(self) -> None:
        self.assert_router([], True)
        self.assert_router(["network", "inspect", "status"], True)
        self.assert_router(["network", "ls", "is-enabled"], True)
        self.assert_router(["network", "inspect"], False)
        self.assert_router(["network", "inspect", "restart"], False)
        self.assert_router(["Network", "inspect", "status"], False)

    def test_bounded_repeated_tail(self) -> None:
        self.assert_router(["somecmd", "one"], True)
        self.assert_router(["somecmd", "one", "two"], True)
        self.assert_router(["somecmd"], False)
        self.assert_router(["somecmd", "one", "two", "three"], False)

    def test_omitted_variants_preserve_unrestricted_positionals(self) -> None:
        open_policy = policy("open", {"mode": "whitelist"})
        with patch.dict(COMMAND_POLICIES, {"open": open_policy}, clear=True):
            actual, reason = validate_pipeline(
                single("open", "any", "positional", "sequence")
            )
        self.assertTrue(actual, msg=reason)

    def test_flags_and_values_are_removed_before_positional_matching(self) -> None:
        inspect_policy = policy(
            "inspect",
            {
                "mode": "whitelist",
                "flags": [
                    {"flag": "--format", "value_pattern": "(?:json|yaml)"},
                    {"flag": "--no-pager", "value_pattern": None},
                ],
                "positional_variants": [["status", "[A-Za-z0-9_.@:-]+"]],
            },
        )
        with patch.dict(COMMAND_POLICIES, {"inspect": inspect_policy}, clear=True):
            actual, reason = validate_pipeline(
                single(
                    "inspect",
                    "--format",
                    "json",
                    "status",
                    "service",
                    "--no-pager",
                )
            )
        self.assertTrue(actual, msg=reason)

    def test_end_of_options_makes_dash_prefixed_token_positional(self) -> None:
        dash_policy = policy(
            "dash",
            {"mode": "whitelist", "positional_variants": [["-.+"]]},
        )
        with patch.dict(COMMAND_POLICIES, {"dash": dash_policy}, clear=True):
            accepted, accepted_reason = validate_pipeline(
                single("dash", "--", "-literal")
            )
            rejected, _ = validate_pipeline(single("dash", "-literal"))
        self.assertTrue(accepted, msg=accepted_reason)
        self.assertFalse(rejected)

    def test_shell_syntax_in_consumed_flag_value_is_literal(self) -> None:
        expansion_policy = policy(
            "expand",
            {
                "mode": "whitelist",
                "flags": [{"flag": "--value", "value_pattern": ".*"}],
            },
        )
        with patch.dict(COMMAND_POLICIES, {"expand": expansion_policy}, clear=True):
            accepted, reason = validate_pipeline(single("expand", "--value", "$VALUE"))
        self.assertTrue(accepted, msg=reason)


class FlagNormalizationTests(unittest.TestCase):
    REPORT_POLICY = policy(
        "report",
        {
            "mode": "whitelist",
            "flags": [
                {
                    "flag": "--format",
                    "value_pattern": "(?:json|yaml|text|text-compact)",
                },
                {"flag": "--limit", "value_pattern": "[1-9][0-9]{0,3}"},
                {"flag": "--no-pager", "value_pattern": None},
            ],
            "positional_variants": [[]],
        },
    )

    def validate_report(self, *arguments: str) -> tuple[bool, str]:
        with patch.dict(COMMAND_POLICIES, {"report": self.REPORT_POLICY}, clear=True):
            return validate_pipeline(single("report", *arguments))

    def test_separate_and_inline_long_values_are_equivalent(self) -> None:
        for arguments in (
            ("--format", "json", "--limit", "250", "--no-pager"),
            ("--format=json", "--limit=250", "--no-pager"),
        ):
            with self.subTest(arguments=arguments):
                accepted, reason = self.validate_report(*arguments)
                self.assertTrue(accepted, msg=reason)

    def test_invalid_value_error_is_actionable(self) -> None:
        accepted, reason = self.validate_report(
            "--format", "xml", "--limit", "250", "--no-pager"
        )
        self.assertFalse(accepted)
        for fragment in (
            "not executed",
            "report",
            "--format",
            "'xml'",
            "(?:json|yaml|text|text-compact)",
            "case-sensitive",
            "complete value",
        ):
            self.assertIn(fragment, reason)

    def test_valueless_flag_rejects_assignment(self) -> None:
        accepted, reason = self.validate_report(
            "--format", "json", "--limit", "250", "--no-pager=true"
        )
        self.assertFalse(accepted)
        self.assertIn("accepts no value", reason)
        self.assertIn("use '--no-pager'", reason)

    def test_missing_value_is_rejected(self) -> None:
        accepted, reason = self.validate_report("--format")
        self.assertFalse(accepted)
        self.assertIn("requires exactly one value", reason)

    def test_short_attached_value_and_explicit_bundling(self) -> None:
        scan_policy = policy(
            "scan",
            {
                "mode": "whitelist",
                "allows_flag_bundling": True,
                "flags": [
                    {"flag": "-z", "value_pattern": None},
                    {"flag": "-v", "value_pattern": None},
                    {"flag": "-w", "value_pattern": "[1-9][0-9]*"},
                ],
                "require_flags": ["-z"],
            },
        )
        with patch.dict(COMMAND_POLICIES, {"scan": scan_policy}, clear=True):
            for pipeline in (
                single("scan", "-z", "-w", "5", "host"),
                single("scan", "-z", "-w5", "host"),
                single("scan", "-zvw5", "host"),
            ):
                with self.subTest(pipeline=pipeline):
                    accepted, reason = validate_pipeline(pipeline)
                    self.assertTrue(accepted, msg=reason)

    def test_bundling_is_disabled_by_default(self) -> None:
        separate_policy = policy(
            "separate",
            {
                "mode": "whitelist",
                "flags": [
                    {"flag": "-a", "value_pattern": None},
                    {"flag": "-v", "value_pattern": None},
                ],
            },
        )
        with patch.dict(COMMAND_POLICIES, {"separate": separate_policy}, clear=True):
            accepted, _ = validate_pipeline(single("separate", "-av"))
        self.assertFalse(accepted)

    def test_exact_flag_precedes_attached_value_interpretation(self) -> None:
        exact_policy = policy(
            "probe",
            {
                "mode": "whitelist",
                "flags": [
                    {"flag": "-n", "value_pattern": "[0-9]+"},
                    {"flag": "-nBAD", "value_pattern": None},
                ],
            },
        )
        with patch.dict(COMMAND_POLICIES, {"probe": exact_policy}, clear=True):
            accepted, reason = validate_pipeline(single("probe", "-nBAD"))
        self.assertTrue(accepted, msg=reason)


class PolicySchemaTests(unittest.TestCase):
    def assert_invalid(self, raw_config: object, fragment: str) -> None:
        with self.assertRaisesRegex(ValueError, fragment):
            policy("invalid", raw_config)

    def test_invalid_policy_shapes_fail_closed(self) -> None:
        cases: tuple[tuple[object, str], ...] = (
            ({"mode": "whitelist", "flags": ["-n"]}, "must be an object"),
            (
                {"mode": "whitelist", "flags": [{"flag": "-n"}]},
                "must contain both",
            ),
            (
                {"mode": "whitelist", "flags": [{"flag": "-n", "value_pattern": "["}]},
                "not a valid regular expression",
            ),
            ({"mode": "whitelist", "positional_variants": []}, "non-empty"),
            (
                {"mode": "blacklist", "positional_variants": [["status"]]},
                "only in whitelist mode",
            ),
            (
                {
                    "mode": "permissive",
                    "flags": [{"flag": "-n", "value_pattern": None}],
                },
                "cannot declare 'flags'",
            ),
            (
                {
                    "mode": "whitelist",
                    "positional_variants": [
                        {"args": [], "rest_pattern": ".+", "min_rest": 2, "max_rest": 1}
                    ],
                },
                "0 <= min_rest <= max_rest",
            ),
            (
                {"handler": "docker", "positional_variants": [["ps"]]},
                "requires mode 'whitelist'",
            ),
            (
                {"handler": "docker", "mode": "whitelist"},
                "requires 'positional_variants'",
            ),
            (
                {
                    "handler": "docker",
                    "mode": "whitelist",
                    "positional_variants": [["ps"]],
                    "targets": [{"host": "loopback"}],
                },
                "unknown field",
            ),
            ({"mode": "whitelist", "unknown": True}, "unknown field"),
        )
        for raw_config, fragment in cases:
            with self.subTest(fragment=fragment):
                self.assert_invalid(raw_config, fragment)

    def test_pattern_length_boundary(self) -> None:
        policy(
            "valid",
            {
                "mode": "whitelist",
                "flags": [
                    {"flag": "--value", "value_pattern": "a" * MAX_PATTERN_LENGTH}
                ],
            },
        )
        self.assert_invalid(
            {
                "mode": "whitelist",
                "flags": [
                    {
                        "flag": "--value",
                        "value_pattern": "a" * (MAX_PATTERN_LENGTH + 1),
                    }
                ],
            },
            "pattern limit",
        )

    def test_value_and_positional_token_length_boundaries(self) -> None:
        length_policy = policy(
            "length",
            {
                "mode": "whitelist",
                "flags": [{"flag": "--value", "value_pattern": ".{1,4096}"}],
                "positional_variants": [[".{1,4096}"]],
            },
        )
        with patch.dict(COMMAND_POLICIES, {"length": length_policy}, clear=True):
            accepted, accepted_reason = validate_pipeline(
                single(
                    "length",
                    "--value",
                    "v" * MAX_POLICY_TOKEN_LENGTH,
                    "p" * MAX_POLICY_TOKEN_LENGTH,
                )
            )
            long_value, _ = validate_pipeline(
                single(
                    "length",
                    "--value",
                    "v" * (MAX_POLICY_TOKEN_LENGTH + 1),
                    "ok",
                )
            )
            long_positional, _ = validate_pipeline(
                single(
                    "length",
                    "--value",
                    "ok",
                    "p" * (MAX_POLICY_TOKEN_LENGTH + 1),
                )
            )
        self.assertTrue(accepted, msg=accepted_reason)
        self.assertFalse(long_value)
        self.assertFalse(long_positional)


class DiscoveryTests(unittest.TestCase):
    def test_discovery_exposes_effective_syntax(self) -> None:
        report_policy = FlagNormalizationTests.REPORT_POLICY
        with patch.dict(COMMAND_POLICIES, {"report": report_policy}, clear=True):
            raw_result: object = json.loads(ssh_list_allowed_commands())
        self.assertIsInstance(raw_result, dict)
        result = cast(dict[str, object], raw_result)
        contract = cast(dict[str, object], result["pipeline_contract"])
        self.assertEqual(contract["stage_fields"], ["command", "arguments"])
        commands = cast(dict[str, object], result["commands"])
        report = cast(dict[str, object], commands["report"])
        self.assertEqual(report["allows_flag_bundling"], False)
        self.assertEqual(report["pattern_matching"], "case-sensitive full-string")
        self.assertEqual(report["positional_variants"], [[]])
        flags = cast(list[dict[str, object]], report["allowed_flags"])
        self.assertEqual(flags[0]["value_pattern"], "(?:json|yaml|text|text-compact)")
        self.assertIsNone(flags[2]["value_pattern"])

    def test_discovery_explains_policy_validated_docker_exec(self) -> None:
        policies = dict(DockerHandlerTests.POLICIES)
        with patch.dict(COMMAND_POLICIES, policies, clear=True):
            raw_result: object = json.loads(ssh_list_allowed_commands())
        result = cast(dict[str, object], raw_result)
        commands = cast(dict[str, object], result["commands"])
        docker = cast(dict[str, object], commands["docker"])
        self.assertEqual(docker["mode"], "handler:docker")
        self.assertEqual(docker["handler"], "docker")
        self.assertIn("positional_variants", docker)
        exec_info = cast(dict[str, object], docker["docker_exec"])
        self.assertEqual(
            exec_info["syntax"],
            "docker exec <container> <command> [arguments...]",
        )
        use_when = cast(str, exec_info["use_when"])
        self.assertIn("unavailable on the host", use_when)
        self.assertIn("docker ps", use_when)
        container = cast(str, exec_info["container"])
        self.assertIn("accepted by Docker", container)
        self.assertEqual(exec_info["docker_options"], False)
        inner_commands = cast(str, exec_info["inner_commands"])
        self.assertIn("effective command policies", inner_commands)

    def test_rule_description_and_dry_run_explain_correction_path(self) -> None:
        rules = ssh_describe_validation_rules()
        self.assertIn("case-sensitive full-string matching", rules)
        self.assertIn("allows_flag_bundling", rules)
        self.assertIn("positional_variants", rules)
        self.assertIn("Security status", rules)

        with patch.dict(
            COMMAND_POLICIES,
            {"report": FlagNormalizationTests.REPORT_POLICY},
            clear=True,
        ):
            result = ssh_validate_command(
                single("report", "--format", "xml", "--limit", "250", "--no-pager")
            )
        self.assertIn("INVALID", result)
        self.assertIn("not executed", result)


class ExecutionValidationPathTests(unittest.IsolatedAsyncioTestCase):
    async def test_execution_uses_the_same_validator(self) -> None:
        pipeline = single("report", "--format", "xml")
        with (
            patch(
                "safe_ssh_mcp._validate_normalized_pipeline",
                return_value=(False, "rejected by shared validator"),
            ) as validator,
            patch("safe_ssh_mcp.get_ssh_connection") as connection,
            self.assertRaisesRegex(ValueError, "rejected by shared validator"),
        ):
            await execute_ssh_command("host", pipeline)
        validator.assert_called_once_with(pipeline)
        connection.assert_not_called()
