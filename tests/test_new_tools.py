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

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from safe_ssh_mcp import (
    CommandStage,
    initialize_command_policies,
    mcp,
    ssh_describe_validation_rules,
    ssh_execute,
    ssh_list_allowed_commands,
    ssh_test_connection,
    ssh_validate_command,
    validate_pipeline,
)

initialize_command_policies(REPOSITORY_ROOT / "policies")


def single(command: str, *arguments: str) -> list[CommandStage]:
    return [{"command": command, "arguments": list(arguments)}]


class DiscoveryToolTests(unittest.TestCase):
    def test_list_allowed_commands_includes_pipeline_contract(self) -> None:
        raw_result: object = json.loads(ssh_list_allowed_commands())
        result = cast(dict[str, object], raw_result)
        contract = cast(dict[str, object], result["pipeline_contract"])
        self.assertEqual(contract["parameter"], "pipeline")
        self.assertEqual(contract["stage_fields"], ["command", "arguments"])
        self.assertIsInstance(contract["single_command_example"], list)
        self.assertIsInstance(contract["pipeline_example"], list)

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
        result = ssh_validate_command(
            [
                {"command": "uptime", "arguments": []},
                {"command": "rm", "arguments": ["-rf", "/tmp/test"]},
            ]
        )
        self.assertIn("INVALID", result)
        self.assertIn("Pipeline stage 2", result)
        self.assertIn("ssh_list_allowed_commands", result)

    def test_rule_description_explains_structured_pipeline(self) -> None:
        description = ssh_describe_validation_rules()
        self.assertIn("STRUCTURED PIPELINE INPUT", description)
        self.assertIn("shlex.join", description)
        self.assertIn("final stage's exit code", description)


class McpSchemaTests(unittest.IsolatedAsyncioTestCase):
    async def test_tool_names_reflect_download_removal(self) -> None:
        tools = await mcp.list_tools()
        tool_names = {tool.name for tool in tools}
        self.assertNotIn("ssh_download", tool_names)
        self.assertEqual(
            tool_names,
            {
                "ssh_describe_validation_rules",
                "ssh_execute",
                "ssh_list_allowed_commands",
                "ssh_list_hosts",
                "ssh_test_connection",
                "ssh_validate_command",
            },
        )

    async def test_execute_and_validate_expose_pipeline_schema(self) -> None:
        tools = await mcp.list_tools()
        schemas = {
            tool.name: cast(dict[str, object], tool.input_schema)
            for tool in tools
            if tool.name in {"ssh_execute", "ssh_validate_command"}
        }
        self.assertEqual(set(schemas), {"ssh_execute", "ssh_validate_command"})
        for schema in schemas.values():
            properties = cast(dict[str, object], schema["properties"])
            self.assertIn("pipeline", properties)
            self.assertNotIn("command", properties)
            definitions = cast(dict[str, object], schema["$defs"])
            stage_schema = cast(dict[str, object], definitions["CommandStage"])
            self.assertEqual(stage_schema["additionalProperties"], False)

    async def test_execute_description_explains_container_fallback(self) -> None:
        tools = await mcp.list_tools()
        execute_tool = next(tool for tool in tools if tool.name == "ssh_execute")
        description = execute_tool.description or ""
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
            result = await ssh_test_connection("target")
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
            result = await ssh_execute("target", single("uptime"))

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
