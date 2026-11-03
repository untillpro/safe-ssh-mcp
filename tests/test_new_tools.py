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
"""Tests for agent-facing discovery and structured validation tools."""

import json
import sys
import unittest
from io import TextIOWrapper
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, patch

from mcp.server.mcpserver.exceptions import ToolError

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from safe_ssh_mcp import (
    COMMAND_POLICIES,
    CommandPolicy,
    CommandStage,
    initialize_command_policies,
    mcp,
    safe_ssh_describe_validation_rules,
    safe_ssh_execute,
    safe_ssh_get_command_rules,
    safe_ssh_list_allowed_commands,
    safe_ssh_test_connection,
    safe_ssh_validate_command,
    validate_pipeline,
)

initialize_command_policies(REPOSITORY_ROOT / "config" / "policies")


def single(command: str, *arguments: str) -> list[CommandStage]:
    return [{"command": command, "arguments": list(arguments)}]


class DiscoveryToolTests(unittest.TestCase):
    def test_listing_contains_sorted_names_and_count_only(self) -> None:
        with patch.dict(
            COMMAND_POLICIES, {"zulu": {}, "alpha": {"mode": "whitelist"}}, clear=True
        ):
            raw_result: object = json.loads(safe_ssh_list_allowed_commands())
        self.assertEqual(
            raw_result, {"total_commands": 2, "commands": ["alpha", "zulu"]}
        )

    def test_listing_can_report_an_empty_registry(self) -> None:
        with patch.dict(COMMAND_POLICIES, {}, clear=True):
            raw_result: object = json.loads(safe_ssh_list_allowed_commands())
        self.assertEqual(raw_result, {"total_commands": 0, "commands": []})

    def test_command_rules_include_pipeline_contract(self) -> None:
        raw_result: object = json.loads(
            safe_ssh_get_command_rules(["docker", "grep", "jq"])
        )
        result = cast(dict[str, object], raw_result)
        self.assertEqual(set(result), {"commands", "pipeline_contract"})
        commands = cast(dict[str, object], result["commands"])
        self.assertEqual(list(commands), ["docker", "grep", "jq"])
        contract = cast(dict[str, object], result["pipeline_contract"])
        self.assertEqual(contract["parameter"], "pipeline")
        self.assertEqual(contract["stage_fields"], ["command", "arguments"])
        self.assertIsInstance(contract["single_command_example"], list)
        self.assertIsInstance(contract["pipeline_example"], list)

    def test_batch_rules_deduplicate_and_skip_unselected_policies(self) -> None:
        policies: dict[str, CommandPolicy] = {
            "unselected": {},
            "strict": {"mode": "whitelist"},
            "open": {"mode": "permissive"},
        }
        with patch.dict(COMMAND_POLICIES, policies, clear=True):
            raw_result: object = json.loads(
                safe_ssh_get_command_rules(["open", "strict", "open"])
            )
        result = cast(dict[str, object], raw_result)
        commands = cast(dict[str, dict[str, object]], result["commands"])
        self.assertEqual(list(commands), ["open", "strict"])
        self.assertEqual(commands["open"]["mode"], "permissive")
        self.assertEqual(commands["strict"]["mode"], "whitelist")
        self.assertNotIn("unselected", commands)
        self.assertNotIn("_compiled", json.dumps(result))

    def test_invalid_batch_requests_raise_actionable_tool_errors(self) -> None:
        invalid_requests: tuple[object, ...] = (
            None,
            "docker",
            {},
            ("docker",),
            1,
            True,
            [],
            [""],
            [" "],
            [None],
            [1],
            ["docker", ""],
        )
        for request in invalid_requests:
            with (
                self.subTest(request=request),
                self.assertRaisesRegex(ToolError, "non-empty"),
            ):
                safe_ssh_get_command_rules(cast(list[str], request))

    def test_unknown_names_reject_the_whole_batch_before_describing_policies(
        self,
    ) -> None:
        requests = (
            ["docker", "missing", "missing"],
            ["Docker"],
            ["docker node ls"],
            [" docker"],
            ["docker "],
            ["*"],
        )
        for request in requests:
            with (
                self.subTest(request=request),
                patch("safe_ssh_mcp._describe_command_policy") as describe,
                self.assertRaisesRegex(ToolError, "Unknown command name") as error,
            ):
                safe_ssh_get_command_rules(request)
            describe.assert_not_called()
            self.assertIn("safe_ssh_list_allowed_commands", str(error.exception))
            if "missing" in request:
                self.assertEqual(str(error.exception).count("'missing'"), 1)

    def test_curl_rules_expose_configured_and_implicit_handler_constraints(
        self,
    ) -> None:
        raw_result: object = json.loads(safe_ssh_get_command_rules(["curl"]))
        result = cast(dict[str, object], raw_result)
        commands = cast(dict[str, dict[str, object]], result["commands"])
        curl = commands["curl"]
        self.assertEqual(curl["mode"], "handler:curl")
        self.assertEqual(curl["handler"], "curl")
        self.assertEqual(curl["require_first"], "--disable")
        self.assertEqual(curl["single_request"], True)
        self.assertEqual(curl["netrc_file_paths"], ["/dev/stdin"])
        self.assertEqual(curl["targets"], [{"host": "loopback"}])
        self.assertIn("--noproxy", cast(list[str], curl["required_flags"]))
        rules = "\n".join(cast(list[str], curl["handler_rules"]))
        self.assertIn("literal value '*'", rules)
        self.assertIn("positive numeric", rules)
        self.assertIn("file-input", rules)
        self.assertIn("credentials", rules)
        self.assertNotIn("_compiled", json.dumps(result))

    def test_handler_defaults_and_overrides_are_reported_inside_subcommands(
        self,
    ) -> None:
        for single_request in (True, False):
            with self.subTest(single_request=single_request):
                handler: CommandPolicy = {"handler": "curl"}
                if not single_request:
                    handler["single_request"] = False
                    handler["netrc_file_paths"] = ["/custom/netrc"]
                router: CommandPolicy = {
                    "mode": "whitelist",
                    "subcommands": {"fetch": handler},
                }
                with patch.dict(COMMAND_POLICIES, {"router": router}, clear=True):
                    raw_result: object = json.loads(
                        safe_ssh_get_command_rules(["router"])
                    )
                result = cast(dict[str, object], raw_result)
                commands = cast(dict[str, dict[str, object]], result["commands"])
                children = cast(
                    dict[str, dict[str, object]], commands["router"]["subcommands"]
                )
                fetch = children["fetch"]
                self.assertEqual(fetch["single_request"], single_request)
                self.assertEqual(fetch["targets"], [])
                self.assertNotIn("require_first", fetch)
                self.assertEqual(
                    fetch["netrc_file_paths"],
                    ["/dev/stdin"] if single_request else ["/custom/netrc"],
                )
                self.assertIn("handler_rules", fetch)

    def test_general_rules_are_independent_of_live_policies(self) -> None:
        with patch.dict(COMMAND_POLICIES, {}, clear=True):
            general_rules = safe_ssh_describe_validation_rules()
        with patch.dict(
            COMMAND_POLICIES,
            {
                "private-probe": {
                    "handler": "curl",
                    "targets": [{"host": "private.example"}],
                }
            },
            clear=True,
        ):
            configured_rules = safe_ssh_describe_validation_rules()
        self.assertEqual(general_rules, configured_rules)
        self.assertNotIn("private-probe", configured_rules)
        self.assertNotIn("private.example", configured_rules)
        self.assertNotIn("POLICY (live)", configured_rules)
        self.assertNotIn("POLICIES (live)", configured_rules)

    def test_discovery_and_dry_runs_make_no_ssh_connections(self) -> None:
        with (
            patch("safe_ssh_mcp.get_ssh_connection") as connection,
            patch("safe_ssh_mcp.execute_ssh_command") as execute,
        ):
            safe_ssh_list_allowed_commands()
            safe_ssh_get_command_rules(["docker", "curl"])
            safe_ssh_describe_validation_rules()
            result = safe_ssh_validate_command(single("docker", "node", "ls"))
        connection.assert_not_called()
        execute.assert_not_called()
        self.assertIn("VALID:", result)
        self.assertIn("command policy", result)
        self.assertNotIn("will execute successfully", result)

    def test_invalid_stored_policies_raise_tool_errors(self) -> None:
        with (
            patch.dict(COMMAND_POLICIES, {"broken": {}}, clear=True),
            self.assertRaisesRegex(ToolError, "explicitly declare 'mode'"),
        ):
            safe_ssh_get_command_rules(["broken"])

    def test_malformed_dry_run_points_to_progressive_discovery(self) -> None:
        result = safe_ssh_validate_command([])
        self.assertIn("INVALID:", result)
        self.assertIn("safe_ssh_get_command_rules", result)
        self.assertIn("safe_ssh_describe_validation_rules", result)

    def test_validation_examples_use_structured_stages(self) -> None:
        cases: tuple[tuple[list[CommandStage], bool], ...] = (
            (single("ls", "-la"), True),
            (single("cat", "file.txt"), True),
            (single("grep", "-i", "error", "/var/log/app.log"), True),
            (single("find", ".", "-name", "*.txt"), True),
            (single("rm", "file.txt"), False),
            (single("find", ".", "-delete"), False),
            (single("curl", "https://example.com"), False),
        )
        for pipeline, expected in cases:
            with self.subTest(pipeline=pipeline):
                accepted, reason = validate_pipeline(pipeline)
                self.assertEqual(accepted, expected, msg=reason)

    def test_dry_run_error_identifies_stage_and_correction_tools(self) -> None:
        result = safe_ssh_validate_command(
            [
                {"command": "uptime", "arguments": []},
                {"command": "rm", "arguments": ["-rf", "/tmp/test"]},
            ]
        )
        self.assertIn("INVALID", result)
        self.assertIn("Pipeline stage 2", result)
        self.assertIn("safe_ssh_list_allowed_commands", result)
        self.assertIn("safe_ssh_get_command_rules", result)

    def test_rule_description_explains_shared_semantics(self) -> None:
        description = safe_ssh_describe_validation_rules()
        self.assertIn("Arguments are literal", description)
        self.assertIn("final stage's exit status", description)
        self.assertIn("policy acceptance only", description)


class McpSchemaTests(unittest.IsolatedAsyncioTestCase):
    async def test_tool_names_use_safe_ssh_prefix(self) -> None:
        tools = await mcp.list_tools()
        tool_names = {tool.name for tool in tools}
        self.assertNotIn("ssh_download", tool_names)
        self.assertEqual(
            tool_names,
            {
                "safe_ssh_describe_validation_rules",
                "safe_ssh_execute",
                "safe_ssh_get_command_rules",
                "safe_ssh_list_allowed_commands",
                "safe_ssh_list_hosts",
                "safe_ssh_test_connection",
                "safe_ssh_validate_command",
            },
        )

    async def test_progressive_discovery_schema_and_tool_guidance(self) -> None:
        tools = await mcp.list_tools()
        indexed = {tool.name: tool for tool in tools}
        rule_schema = cast(
            dict[str, object], indexed["safe_ssh_get_command_rules"].input_schema
        )
        self.assertEqual(rule_schema["required"], ["commands"])
        properties = cast(dict[str, dict[str, object]], rule_schema["properties"])
        commands = properties["commands"]
        self.assertEqual(commands["type"], "array")
        self.assertEqual(cast(dict[str, object], commands["items"])["type"], "string")
        index_schema = cast(
            dict[str, object], indexed["safe_ssh_list_allowed_commands"].input_schema
        )
        self.assertEqual(index_schema.get("properties"), {})
        for name in (
            "safe_ssh_list_allowed_commands",
            "safe_ssh_execute",
            "safe_ssh_validate_command",
            "safe_ssh_describe_validation_rules",
        ):
            with self.subTest(name=name):
                self.assertIn(
                    "safe_ssh_get_command_rules", indexed[name].description or ""
                )

    async def test_policy_rejection_points_to_selected_rules_before_connecting(
        self,
    ) -> None:
        with (
            patch("safe_ssh_mcp.get_ssh_connection") as connection,
            self.assertRaises(ToolError) as error,
        ):
            await safe_ssh_execute("target", single("rm", "file.txt"))
        connection.assert_not_called()
        self.assertIn("safe_ssh_list_allowed_commands", str(error.exception))
        self.assertIn("safe_ssh_get_command_rules", str(error.exception))

    async def test_connection_error_is_not_reported_as_a_discovery_problem(
        self,
    ) -> None:
        with (
            patch(
                "safe_ssh_mcp.execute_ssh_command",
                new=AsyncMock(side_effect=ValueError("SSH authentication failed")),
            ),
            self.assertRaises(ToolError) as error,
        ):
            await safe_ssh_execute("target", single("uptime"))
        self.assertEqual(str(error.exception), "SSH authentication failed")

    async def test_execute_and_validate_expose_pipeline_schema(self) -> None:
        tools = await mcp.list_tools()
        schemas = {
            tool.name: cast(dict[str, object], tool.input_schema)
            for tool in tools
            if tool.name in {"safe_ssh_execute", "safe_ssh_validate_command"}
        }
        self.assertEqual(
            set(schemas), {"safe_ssh_execute", "safe_ssh_validate_command"}
        )
        for schema in schemas.values():
            properties = cast(dict[str, object], schema["properties"])
            self.assertIn("pipeline", properties)
            self.assertNotIn("command", properties)
            definitions = cast(dict[str, object], schema["$defs"])
            stage_schema = cast(dict[str, object], definitions["CommandStage"])
            self.assertEqual(stage_schema["additionalProperties"], False)

    async def test_execute_description_explains_container_fallback(self) -> None:
        tools = await mcp.list_tools()
        execute_tool = next(tool for tool in tools if tool.name == "safe_ssh_execute")
        description = execute_tool.description or ""
        self.assertIn("Inspect and diagnose remote hosts over SSH", description)
        self.assertIn("diagnostic command is unavailable on the host", description)
        self.assertIn("docker ps", description)
        self.assertIn("docker exec <container> <command>", description)

    async def test_connection_failure_is_actionable_to_the_agent(self) -> None:
        with patch(
            "safe_ssh_mcp.get_ssh_connection",
            side_effect=ValueError(
                "SSH authentication failed for 'target'. Check the configured "
                "IdentityFile and loaded SSH-agent keys."
            ),
        ):
            result = await safe_ssh_test_connection("target")
        self.assertIn("authentication failed", result)
        self.assertIn("IdentityFile", result)

    async def test_truncated_result_reports_unavailable_exit_status(self) -> None:
        with patch(
            "safe_ssh_mcp.execute_ssh_command",
            new=AsyncMock(
                return_value=(
                    "retained output\n\n[truncated - exceeded 50KB limit]",
                    "",
                    None,
                )
            ),
        ):
            result = await safe_ssh_execute("target", single("uptime"))

        self.assertIn("Exit status: unavailable", result)
        self.assertIn("[truncated - exceeded 50KB limit]", result)
        self.assertNotIn("Exit code:", result)


def main() -> None:
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if isinstance(stream, TextIOWrapper):
            stream.reconfigure(encoding="utf-8")
    unittest.main()


if __name__ == "__main__":
    main()
