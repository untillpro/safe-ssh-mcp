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
"""
SSH MCP Server - Provides SSH access to remote hosts via MCP protocol.

This server enables MCP clients (like Augment Code, Claude Desktop) to execute
commands on remote hosts using SSH with command validation for safety.
"""

# Malformed trusted-policy data is reported uniformly as ValueError to callers.
# ruff: noqa: TRY004

import asyncio
import ipaddress
import logging
import os
import platform
import re
import shlex
import sys
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from io import TextIOWrapper
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

import asyncssh
import yaml
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from typing_extensions import TypedDict


class CommandStage(TypedDict, closed=True):
    command: str
    arguments: list[str]


class UrlTarget(TypedDict, total=False):
    scheme: str  # exact scheme, or "*"/omitted for http+https
    host: str  # exact name, IP, CIDR (e.g. 127.0.0.0/8), or "loopback"
    port: int | str  # exact port, or "*"/omitted for any port
    path_prefix: str  # path prefix, or "*"/omitted for any path


class FlagPolicy(TypedDict):
    flag: str
    value_pattern: str | None


class PositionalRestVariant(TypedDict):
    args: list[str]
    rest_pattern: str
    min_rest: int
    max_rest: int


PositionalVariant = list[str] | PositionalRestVariant
CompiledPositionalVariant = tuple[
    tuple[re.Pattern[str], ...],
    re.Pattern[str] | None,
    int,
    int,
]


class CommandPolicy(TypedDict, total=False):
    mode: str
    flags: list[FlagPolicy]
    require_flags: list[str]
    allows_flag_bundling: bool
    positional_variants: list[PositionalVariant]
    _compiled_flags: dict[str, re.Pattern[str] | None]
    _compiled_positional_variants: list[CompiledPositionalVariant]
    # Custom-handler policy (see COMMAND_HANDLERS). The named handler owns any
    # command-specific grammar and may compose with the generic policy fields.
    handler: str
    require_first: str
    single_request: bool
    targets: list[UrlTarget]
    netrc_file_paths: list[str]


class DockerExecInfo(TypedDict):
    syntax: str
    use_when: str
    container: str
    docker_options: bool
    inner_commands: str


class CommandInfo(TypedDict, total=False):
    mode: str
    allowed_flags: list[FlagPolicy]
    blocked_flags: list[FlagPolicy]
    required_flags: list[str]
    allows_flag_bundling: bool
    positional_variants: list[PositionalVariant]
    pattern_matching: str
    handler: str
    targets: list[UrlTarget]
    docker_exec: DockerExecInfo


class PipelineContract(TypedDict):
    parameter: str
    stage_fields: list[str]
    max_stages: int
    max_arguments_per_stage: int
    max_token_characters: int
    max_rendered_utf8_bytes: int
    single_command_example: list[CommandStage]
    pipeline_example: list[CommandStage]


class AllowedCommands(TypedDict):
    total_commands: int
    pipeline_contract: PipelineContract
    commands: dict[str, CommandInfo]


for stream in (sys.stdin, sys.stdout, sys.stderr):
    if isinstance(stream, TextIOWrapper):
        stream.reconfigure(encoding="utf-8")

SCRIPT_DIR = Path(__file__).resolve().parent
POLICY_DIR_ENV = "SAFE_SSH_MCP_POLICY_DIR"
LOG_DIR_ENV = "SAFE_SSH_MCP_LOG_DIR"
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
logger.propagate = False


def _resolve_configured_directory(environment_variable: str, default_name: str) -> Path:
    """Resolve one configured directory relative to this script."""
    configured_value = os.environ.get(environment_variable)
    if configured_value is None:
        return SCRIPT_DIR / default_name
    if not configured_value.strip():
        raise ValueError(f"{environment_variable} must not be empty")

    configured_path = Path(configured_value).expanduser()
    if not configured_path.is_absolute():
        configured_path = SCRIPT_DIR / configured_path
    return configured_path.resolve()


def _resolve_directory_relative_to_script(directory: Path) -> Path:
    """Normalize an explicit runtime directory using configuration semantics."""
    resolved_directory = directory.expanduser()
    if not resolved_directory.is_absolute():
        resolved_directory = SCRIPT_DIR / resolved_directory
    return resolved_directory.resolve()


def configure_logging(log_dir: Path | None = None) -> Path:
    """Configure UTF-8 file and stderr logging and return the log file path."""
    resolved_log_dir = (
        _resolve_configured_directory(LOG_DIR_ENV, ".logs")
        if log_dir is None
        else _resolve_directory_relative_to_script(log_dir)
    )
    try:
        resolved_log_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise OSError(
            f"Cannot create log directory {resolved_log_dir}: {error}"
        ) from error
    if not resolved_log_dir.is_dir():
        raise NotADirectoryError(
            f"Log directory is not a directory: {resolved_log_dir}"
        )

    timestamp = datetime.now().strftime("%y%m%d%H%M")
    log_file = resolved_log_dir / f"{timestamp}-{os.getpid()}.log"
    try:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
    except OSError as error:
        raise OSError(f"Cannot open log file {log_file}: {error}") from error

    formatter = logging.Formatter(
        "[%(asctime)s.%(msecs)03d] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(formatter)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)

    previous_handlers = list(logger.handlers)
    logger.handlers.clear()
    for handler in previous_handlers:
        handler.close()
    logger.addHandler(file_handler)
    logger.addHandler(stderr_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return log_file


# Response and timeout limits
COMMAND_TIMEOUT_SECONDS = 10
PROCESS_CLEANUP_TIMEOUT_SECONDS = 1
MAX_RESPONSE_BYTES = 50 * 1024  # 50 KB - agent-friendly response size
STREAM_READ_BYTES = 64 * 1024
DEFAULT_KEEPALIVE_SECONDS = 30
KEEPALIVE_COUNT_MAX = 3
MAX_PATTERN_LENGTH = 1024
MAX_POLICY_TOKEN_LENGTH = 4096
MAX_PIPELINE_STAGES = 16
MAX_ARGUMENTS_PER_STAGE = 128
MAX_RENDERED_PIPELINE_LENGTH = 64 * 1024
MAX_SSH_ALIAS_LENGTH = 255

SSH_CONFIG_PATH = Path.home() / ".ssh" / "config"
KNOWN_HOSTS_PATH = Path.home() / ".ssh" / "known_hosts"
WINDOWS_OPENSSH_AGENT_PIPE = r"\\.\pipe\openssh-ssh-agent"

_POLICY_MODES = frozenset({"permissive", "blacklist", "whitelist"})
_GENERIC_POLICY_FIELDS = frozenset(
    {
        "mode",
        "flags",
        "require_flags",
        "allows_flag_bundling",
        "positional_variants",
    }
)
_CURL_HANDLER_POLICY_FIELDS = frozenset(
    {
        "handler",
        "flags",
        "require_flags",
        "allows_flag_bundling",
        "require_first",
        "single_request",
        "targets",
        "netrc_file_paths",
    }
)
_DOCKER_HANDLER_POLICY_FIELDS = _GENERIC_POLICY_FIELDS | {"handler"}
_HANDLER_POLICY_FIELDS: dict[str, frozenset[str]] = {
    "curl": _CURL_HANDLER_POLICY_FIELDS,
    "docker": _DOCKER_HANDLER_POLICY_FIELDS,
}
_POSITIONAL_REST_FIELDS = frozenset({"args", "rest_pattern", "min_rest", "max_rest"})
_TARGET_FIELDS = frozenset({"scheme", "host", "port", "path_prefix"})
_KNOWN_HANDLERS = frozenset(_HANDLER_POLICY_FIELDS)


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects ambiguous duplicate mapping keys."""


def _construct_unique_mapping(
    loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key: object = loader.construct_object(key_node, deep=deep)
        try:
            is_duplicate = key in mapping
        except TypeError as error:
            raise ValueError("YAML mapping keys must be hashable") from error
        if is_duplicate:
            raise ValueError(f"Duplicate YAML key {key!r}")
        value: object = loader.construct_object(value_node, deep=deep)
        mapping[key] = value
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _policy_context(source: str, cmd_name: str) -> str:
    return f"Policy for command '{cmd_name}' in {source}"


def _compile_policy_pattern(pattern: str, context: str) -> re.Pattern[str]:
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ValueError(
            f"{context} exceeds the {MAX_PATTERN_LENGTH}-character pattern limit"
        )
    try:
        return re.compile(pattern)
    except re.error as error:
        raise ValueError(
            f"{context} is not a valid regular expression: {error}"
        ) from error


def _normalize_flags(
    raw_flags: object, context: str
) -> tuple[list[FlagPolicy], dict[str, re.Pattern[str] | None]]:
    if not isinstance(raw_flags, list):
        raise ValueError(f"{context} field 'flags' must be an array")

    flags: list[FlagPolicy] = []
    compiled_flags: dict[str, re.Pattern[str] | None] = {}
    for index, raw_flag in enumerate(raw_flags):
        flag_context = f"{context} flags[{index}]"
        if not isinstance(raw_flag, dict):
            raise ValueError(
                f"{flag_context} must be an object with 'flag' and 'value_pattern'"
            )
        flag_data: dict[object, object] = cast(dict[object, object], raw_flag)
        unknown_fields = set(flag_data) - {"flag", "value_pattern"}
        if unknown_fields:
            raise ValueError(
                f"{flag_context} has unknown field(s): {', '.join(sorted(map(str, unknown_fields)))}"
            )
        if "flag" not in flag_data or "value_pattern" not in flag_data:
            raise ValueError(
                f"{flag_context} must contain both 'flag' and 'value_pattern'"
            )

        raw_name = flag_data["flag"]
        if (
            not isinstance(raw_name, str)
            or not raw_name.startswith("-")
            or raw_name in {"-", "--"}
            or "=" in raw_name
            or any(character.isspace() for character in raw_name)
        ):
            raise ValueError(f"{flag_context} field 'flag' must be a flag name")
        if raw_name in compiled_flags:
            raise ValueError(f"{flag_context} duplicates flag '{raw_name}'")

        raw_pattern = flag_data["value_pattern"]
        if raw_pattern is not None and not isinstance(raw_pattern, str):
            raise ValueError(
                f"{flag_context} field 'value_pattern' must be a string or null"
            )
        compiled_pattern = (
            _compile_policy_pattern(raw_pattern, f"{flag_context} value_pattern")
            if isinstance(raw_pattern, str)
            else None
        )
        flag: FlagPolicy = {
            "flag": raw_name,
            "value_pattern": raw_pattern,
        }
        flags.append(flag)
        compiled_flags[raw_name] = compiled_pattern

    return flags, compiled_flags


def _normalize_string_list(raw_value: object, field: str, context: str) -> list[str]:
    if not isinstance(raw_value, list) or not all(
        isinstance(item, str) for item in raw_value
    ):
        raise ValueError(f"{context} field '{field}' must be an array of strings")
    return cast(list[str], raw_value).copy()


def _normalize_positional_variants(
    raw_variants: object, context: str
) -> tuple[list[PositionalVariant], list[CompiledPositionalVariant]]:
    if not isinstance(raw_variants, list) or not raw_variants:
        raise ValueError(
            f"{context} field 'positional_variants' must be a non-empty array"
        )

    variants: list[PositionalVariant] = []
    compiled_variants: list[CompiledPositionalVariant] = []
    for index, raw_variant in enumerate(raw_variants):
        variant_context = f"{context} positional_variants[{index}]"
        if isinstance(raw_variant, list):
            if not all(isinstance(item, str) for item in raw_variant):
                raise ValueError(
                    f"{variant_context} must contain only regular-expression strings"
                )
            patterns = cast(list[str], raw_variant).copy()
            compiled = tuple(
                _compile_policy_pattern(pattern, f"{variant_context}[{pattern_index}]")
                for pattern_index, pattern in enumerate(patterns)
            )
            variants.append(patterns)
            compiled_variants.append((compiled, None, 0, 0))
            continue

        if not isinstance(raw_variant, dict):
            raise ValueError(
                f"{variant_context} must be an exact array or a bounded-rest object"
            )
        variant_data: dict[object, object] = cast(dict[object, object], raw_variant)
        unknown_fields = set(variant_data) - _POSITIONAL_REST_FIELDS
        missing_fields = _POSITIONAL_REST_FIELDS - set(variant_data)
        if unknown_fields:
            raise ValueError(
                f"{variant_context} has unknown field(s): {', '.join(sorted(map(str, unknown_fields)))}"
            )
        if missing_fields:
            raise ValueError(
                f"{variant_context} is missing field(s): {', '.join(sorted(missing_fields))}"
            )

        args = _normalize_string_list(variant_data["args"], "args", variant_context)
        raw_rest_pattern = variant_data["rest_pattern"]
        raw_min_rest = variant_data["min_rest"]
        raw_max_rest = variant_data["max_rest"]
        if not isinstance(raw_rest_pattern, str):
            raise ValueError(f"{variant_context} field 'rest_pattern' must be a string")
        if (
            not isinstance(raw_min_rest, int)
            or isinstance(raw_min_rest, bool)
            or not isinstance(raw_max_rest, int)
            or isinstance(raw_max_rest, bool)
            or raw_min_rest < 0
            or raw_max_rest < 0
            or raw_min_rest > raw_max_rest
        ):
            raise ValueError(f"{variant_context} requires 0 <= min_rest <= max_rest")

        rest_variant: PositionalRestVariant = {
            "args": args,
            "rest_pattern": raw_rest_pattern,
            "min_rest": raw_min_rest,
            "max_rest": raw_max_rest,
        }
        compiled_args = tuple(
            _compile_policy_pattern(pattern, f"{variant_context}.args[{pattern_index}]")
            for pattern_index, pattern in enumerate(args)
        )
        compiled_rest = _compile_policy_pattern(
            raw_rest_pattern, f"{variant_context}.rest_pattern"
        )
        variants.append(rest_variant)
        compiled_variants.append(
            (compiled_args, compiled_rest, raw_min_rest, raw_max_rest)
        )

    return variants, compiled_variants


def _normalize_targets(raw_targets: object, context: str) -> list[UrlTarget]:
    if not isinstance(raw_targets, list):
        raise ValueError(f"{context} field 'targets' must be an array")
    targets: list[UrlTarget] = []
    for index, raw_target in enumerate(raw_targets):
        target_context = f"{context} targets[{index}]"
        if not isinstance(raw_target, dict):
            raise ValueError(f"{target_context} must be an object")
        target_data: dict[object, object] = cast(dict[object, object], raw_target)
        unknown_fields = set(target_data) - _TARGET_FIELDS
        if unknown_fields:
            raise ValueError(
                f"{target_context} has unknown field(s): {', '.join(sorted(map(str, unknown_fields)))}"
            )
        raw_host = target_data.get("host")
        if not isinstance(raw_host, str) or not raw_host:
            raise ValueError(
                f"{target_context} field 'host' must be a non-empty string"
            )
        target: UrlTarget = {"host": raw_host}
        for field in ("scheme", "path_prefix"):
            raw_value = target_data.get(field)
            if raw_value is not None:
                if not isinstance(raw_value, str):
                    raise ValueError(
                        f"{target_context} field '{field}' must be a string"
                    )
                target[field] = raw_value  # type: ignore[literal-required]
        raw_port = target_data.get("port")
        if raw_port is not None:
            if isinstance(raw_port, bool) or not isinstance(raw_port, (int, str)):
                raise ValueError(
                    f"{target_context} field 'port' must be an integer or string"
                )
            target["port"] = raw_port
        targets.append(target)
    return targets


def _normalize_command_policy(
    cmd_name: str, raw_config: object, source: str
) -> CommandPolicy:
    context = _policy_context(source, cmd_name)
    if not isinstance(raw_config, dict):
        raise ValueError(f"{context} must be an object")
    config_data: dict[object, object] = cast(dict[object, object], raw_config)

    raw_handler = config_data.get("handler")
    if raw_handler is not None and (
        not isinstance(raw_handler, str) or raw_handler not in _KNOWN_HANDLERS
    ):
        raise ValueError(f"{context} field 'handler' must name a supported handler")
    is_handler = isinstance(raw_handler, str)
    uses_generic_policy = not is_handler or raw_handler == "docker"
    allowed_fields = (
        _HANDLER_POLICY_FIELDS[raw_handler]
        if isinstance(raw_handler, str)
        else _GENERIC_POLICY_FIELDS
    )
    unknown_fields = set(config_data) - allowed_fields
    if unknown_fields:
        raise ValueError(
            f"{context} has unknown field(s): {', '.join(sorted(map(str, unknown_fields)))}"
        )

    normalized: CommandPolicy = {}
    if is_handler:
        normalized["handler"] = raw_handler
    if uses_generic_policy:
        raw_mode = config_data.get("mode", "permissive")
        if not isinstance(raw_mode, str) or raw_mode not in _POLICY_MODES:
            raise ValueError(
                f"{context} field 'mode' must be permissive, blacklist, or whitelist"
            )
        normalized["mode"] = raw_mode
        if raw_handler == "docker" and raw_mode != "whitelist":
            raise ValueError(f"{context} handler 'docker' requires mode 'whitelist'")

    raw_flags = config_data.get("flags", [])
    flags, compiled_flags = _normalize_flags(raw_flags, context)
    if normalized.get("mode") == "permissive" and flags:
        raise ValueError(
            f"{context} cannot declare 'flags' in permissive mode because all flags are allowed"
        )
    if flags or "flags" in config_data:
        normalized["flags"] = flags
    normalized["_compiled_flags"] = compiled_flags

    raw_bundling = config_data.get("allows_flag_bundling", False)
    if not isinstance(raw_bundling, bool):
        raise ValueError(f"{context} field 'allows_flag_bundling' must be boolean")
    normalized["allows_flag_bundling"] = raw_bundling

    if "require_flags" in config_data:
        if uses_generic_policy and normalized.get("mode") != "whitelist":
            raise ValueError(
                f"{context} may use 'require_flags' only in whitelist mode"
            )
        required_flags = _normalize_string_list(
            config_data["require_flags"], "require_flags", context
        )
        unknown_required = [
            flag for flag in required_flags if flag not in compiled_flags
        ]
        if unknown_required:
            raise ValueError(
                f"{context} requires undeclared flag(s): {', '.join(unknown_required)}"
            )
        normalized["require_flags"] = required_flags

    if "positional_variants" in config_data:
        if normalized.get("mode") != "whitelist":
            raise ValueError(
                f"{context} may use 'positional_variants' only in whitelist mode"
            )
        variants, compiled_variants = _normalize_positional_variants(
            config_data["positional_variants"], context
        )
        normalized["positional_variants"] = variants
        normalized["_compiled_positional_variants"] = compiled_variants

    if raw_handler == "docker" and "positional_variants" not in config_data:
        raise ValueError(f"{context} handler 'docker' requires 'positional_variants'")

    if raw_handler == "curl":
        raw_require_first = config_data.get("require_first")
        if raw_require_first is not None:
            if not isinstance(raw_require_first, str):
                raise ValueError(f"{context} field 'require_first' must be a string")
            if raw_require_first not in compiled_flags:
                raise ValueError(
                    f"{context} field 'require_first' names undeclared flag '{raw_require_first}'"
                )
            normalized["require_first"] = raw_require_first

        raw_single_request = config_data.get("single_request")
        if raw_single_request is not None:
            if not isinstance(raw_single_request, bool):
                raise ValueError(f"{context} field 'single_request' must be boolean")
            normalized["single_request"] = raw_single_request

        if "targets" in config_data:
            normalized["targets"] = _normalize_targets(config_data["targets"], context)
        if "netrc_file_paths" in config_data:
            normalized["netrc_file_paths"] = _normalize_string_list(
                config_data["netrc_file_paths"], "netrc_file_paths", context
            )

    return normalized


# Threat model (ADR-002):
#
# Goal: prevent system MODIFICATION and data EXFILTRATION via network.
# Users already have SSH access so reading files is acceptable.
#
# BLOCKED:
#   - File writes/deletes (rm, mv, cp, touch, mkdir, chmod, chown)
#   - Arbitrary shell syntax; only server-inserted pipeline separators exist
#   - Network exfiltration (wget, ssh, scp, rsync); curl only via the
#     target-allowlisted handler below (see ADR-003)
#   - Process control (kill, pkill, sudo, su)
#   - Command execution via flags (find -exec, find -delete)
#   - Archive extraction (tar -x, unzip without -l) -- creates files
#   - Scripting languages with internal exec/write (awk, sed)
#
# ALLOWED:
#   - All read-only operations (file reading, searching, system info)
#   - Server-controlled pipelines of structured command stages
#   - Literal arguments safely quoted before remote-shell execution
#   - curl, only to allowlisted targets (handler mode, see ADR-003)
#   - docker exec, only for commands accepted by the effective policy
#
# Mode assignment:
#   - permissive: command has NO flags/features that modify the system
#   - blacklist:  command has a FEW dangerous flags among many safe ones
#                 (find, sort, date, journalctl, xmllint, yq, ss)
#   - whitelist:  command has flags that write/extract/execute, only safe
#                 flags are listed explicitly
#   - handler:    generic flag/positional validation is insufficient; a
#                 command-specific Python handler inspects values (curl) or
#                 delegates nested grammar back to the policy engine (docker)
#   - REMOVED:    commands with internal exec/write that flag validation
#                 cannot catch (awk: system(), sed: e/w commands)
#
def load_command_policies(policy_dir: Path | None = None) -> dict[str, CommandPolicy]:
    """Load the complete command policy from YAML files."""
    resolved_policy_dir = (
        policy_dir if policy_dir is not None else SCRIPT_DIR / "policies"
    )
    if not resolved_policy_dir.is_dir():
        raise FileNotFoundError(f"Policy directory not found: {resolved_policy_dir}")

    yaml_files = sorted(
        list(resolved_policy_dir.glob("*.yaml"))
        + list(resolved_policy_dir.glob("*.yml"))
    )
    if not yaml_files:
        raise FileNotFoundError(f"No YAML policy files found in {resolved_policy_dir}")

    policies: dict[str, CommandPolicy] = {}
    policy_sources: dict[str, str] = {}

    for yaml_file in yaml_files:
        try:
            with open(yaml_file, encoding="utf-8") as policy_stream:
                raw_policy_data: object = yaml.load(
                    policy_stream, Loader=_UniqueKeySafeLoader
                )
        except (yaml.YAMLError, ValueError) as error:
            raise ValueError(f"Failed to parse {yaml_file.name}: {error}") from error

        if not isinstance(raw_policy_data, dict):
            raise ValueError(f"Policy file {yaml_file.name} root must be an object")

        file_policies: dict[object, object] = cast(
            dict[object, object], raw_policy_data
        )
        for raw_cmd_name, raw_config in file_policies.items():
            if not isinstance(raw_cmd_name, str) or not re.fullmatch(
                r"[A-Za-z0-9_.+-]+", raw_cmd_name
            ):
                raise ValueError(
                    f"Policy file {yaml_file.name} contains an invalid command name"
                )
            previous_source = policy_sources.get(raw_cmd_name)
            if previous_source is not None:
                raise ValueError(
                    f"Duplicate policy for command '{raw_cmd_name}' in "
                    f"{yaml_file.name}; already defined in {previous_source}"
                )
            policies[raw_cmd_name] = _normalize_command_policy(
                raw_cmd_name, raw_config, yaml_file.name
            )
            policy_sources[raw_cmd_name] = yaml_file.name

        logger.info(f"Loaded command policy: {yaml_file.name}")

    if not policies:
        raise ValueError(
            f"No command policies found in YAML files under {resolved_policy_dir}"
        )

    logger.info(
        f"Loaded {len(policies)} commands from {len(yaml_files)} policy file(s)"
    )
    return policies


# YAML files are the sole source of command-specific permissions.
COMMAND_POLICIES: dict[str, CommandPolicy] = {}


def initialize_command_policies(policy_dir: Path | None = None) -> Path:
    """Replace the effective command policy from one complete directory."""
    resolved_policy_dir = (
        _resolve_configured_directory(POLICY_DIR_ENV, "policies")
        if policy_dir is None
        else _resolve_directory_relative_to_script(policy_dir)
    )
    loaded_policies = load_command_policies(resolved_policy_dir)
    COMMAND_POLICIES.clear()
    COMMAND_POLICIES.update(loaded_policies)
    return resolved_policy_dir


def initialize_runtime(
    policy_dir: Path | None = None, log_dir: Path | None = None
) -> tuple[Path, Path]:
    """Initialize logging and the effective command policy."""
    log_file = configure_logging(log_dir)
    resolved_policy_dir = initialize_command_policies(policy_dir)
    return resolved_policy_dir, log_file


# Connections and their creation locks live for the MCP server lifetime.
ssh_connections: dict[str, asyncssh.SSHClientConnection] = {}
ssh_connection_locks: dict[str, asyncio.Lock] = {}


def _split_ssh_config_line(line: str, path: Path, line_number: int) -> list[str]:
    """Split one OpenSSH config line without accepting malformed quoting."""
    try:
        tokens = shlex.split(line, comments=True, posix=False)
    except ValueError as error:
        raise ValueError(
            f"Cannot parse SSH config {path} line {line_number}: malformed quoting"
        ) from error

    tokens = [
        token[1:-1]
        if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}
        else token
        for token in tokens
    ]
    if not tokens:
        return []

    if "=" in tokens[0]:
        keyword, value = tokens[0].split("=", 1)
        tokens = [keyword, value, *tokens[1:]]

    return tokens


def _is_listable_ssh_alias(alias: str) -> bool:
    """Return whether a Host token is useful as a concrete list entry."""
    return (
        len(alias) <= MAX_SSH_ALIAS_LENGTH
        and not alias.startswith("!")
        and "@" not in alias
        and re.fullmatch(r"[A-Za-z0-9_.:+-]+", alias) is not None
    )


def list_ssh_hosts(config_path: Path | None = None) -> list[str]:
    """Return best-effort concrete Host entries from the main SSH config."""
    path = (config_path or SSH_CONFIG_PATH).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"SSH config not found at {path}")
    try:
        contents = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"Cannot read SSH config file {path} as UTF-8") from error

    aliases: set[str] = set()
    for line_number, line in enumerate(contents.splitlines(), start=1):
        try:
            tokens = _split_ssh_config_line(
                line.lstrip("\ufeff") if line_number == 1 else line,
                path,
                line_number,
            )
        except ValueError as error:
            logger.warning(str(error))
            continue
        if tokens and tokens[0].casefold() == "host":
            aliases.update(
                alias for alias in tokens[1:] if _is_listable_ssh_alias(alias)
            )

    return sorted(aliases)


# Command-specific validation handlers.
#
# Some commands cannot be made safe by flag-name validation alone because their
# risk lives in argument VALUES (e.g. curl's URL, --data @file). A handler
# receives the parsed command node and the policy, and validates deny-by-default:
# any token it cannot positively classify as safe causes rejection.

_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}

# curl flags (among those a policy may allow) that consume the following token
# as their value. Hard-coded because it is curl grammar, not policy: it prevents
# a value such as a URL from being misread as a standalone argument, and stops a
# required flag from being silently consumed as another flag's value.
_CURL_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--max-time",
        "--connect-timeout",
        "--url",
        "--data-urlencode",
        "--netrc-file",
        "--noproxy",
    }
)

_DEFAULT_NETRC_PATHS: tuple[str, ...] = ("/dev/stdin",)


def _data_urlencode_reads_file(value: str) -> bool:
    """True if a --data-urlencode value uses the file-input form.

    curl selects the form by the first '=' or '@': '=' (or none) means the value
    is literal content, '@' first means read from a file/stdin. Only the literal
    forms are allowed, so a value that would make curl read a local file is
    rejected while 'name=content' parameters are permitted.
    """
    for ch in value:
        if ch == "=":
            return False
        if ch == "@":
            return True
    return False


def _host_matches(url_host: str, target_host: str) -> bool:
    """Match a URL host against a target host spec.

    The target spec may be an exact name, an IP, a CIDR network (e.g.
    127.0.0.0/8), the keyword "loopback" (any IPv4/IPv6 loopback address), or
    "*" (any host). IP/CIDR matching is done numerically so textual tricks
    (e.g. decimal/octal IP encodings) resolve to the same address.
    """
    spec = target_host.strip().lower().rstrip(".")
    if not spec:
        return False
    if spec == "*":
        return True

    url_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    try:
        url_ip = ipaddress.ip_address(url_host)
    except ValueError:
        url_ip = None

    if spec == "loopback":
        return url_ip is not None and url_ip.is_loopback
    if url_ip is not None:
        try:
            return url_ip in ipaddress.ip_network(spec, strict=False)
        except ValueError:
            pass
    return url_host == spec


def _curl_url_allowed(raw_url: str, targets: list[UrlTarget]) -> tuple[bool, str]:
    """Check a curl URL against the target allowlist (scheme/host/port/path)."""
    split = urlsplit(raw_url)
    scheme = split.scheme.lower()
    if not scheme or not split.netloc:
        return False, f"URL '{raw_url}' must be absolute (scheme://host/...)"
    # Embedded credentials would leak into logs and bypass credential controls.
    if "@" in split.netloc or split.username is not None or split.password is not None:
        return False, "URL must not contain embedded credentials"

    host = (split.hostname or "").lower().rstrip(".")
    if not host:
        return False, f"URL '{raw_url}' has no host"

    # Globbing is active unless --globoff is passed (which this policy does not
    # allow), so curl glob metacharacters could multiply or alter the request.
    # Check per-component after parsing so IPv6 host brackets ([::1]) are allowed
    # while [] / {} elsewhere (host name, path, query) are still rejected.
    for component in (host, split.path, split.query, split.fragment):
        if any(ch in component for ch in "{}[]"):
            return False, "URL globbing is not allowed"
    try:
        port: int | None = (
            split.port if split.port is not None else _DEFAULT_PORTS.get(scheme)
        )
    except ValueError:
        return False, f"URL '{raw_url}' has an invalid port"
    path = split.path or "/"

    for target in targets:
        t_scheme = str(target.get("scheme", "")).lower()
        if t_scheme in ("", "*"):
            if scheme not in _DEFAULT_PORTS:  # only http/https by default
                continue
        elif scheme != t_scheme:
            continue

        if not _host_matches(host, str(target.get("host", ""))):
            continue

        raw_port = target.get("port")
        if raw_port is not None and str(raw_port) != "*":
            try:
                if port != int(raw_port):
                    continue
            except (TypeError, ValueError):
                continue

        prefix = target.get("path_prefix")
        if (
            prefix is not None
            and str(prefix) != "*"
            and not path.startswith(str(prefix))
        ):
            continue

        return True, "OK"

    return False, f"URL '{raw_url}' is not in the allowed target list"


def _target_description(target: UrlTarget) -> str:
    """One-line human/agent-readable description of an allowed target."""
    scheme = str(target.get("scheme") or "http/https")
    host = str(target.get("host") or "?")
    raw_port = target.get("port")
    port = "any-port" if raw_port is None or str(raw_port) == "*" else str(raw_port)
    prefix = target.get("path_prefix")
    path = "any-path" if prefix is None or str(prefix) == "*" else str(prefix)
    return f"{scheme}://{host} ({port}, {path})"


def _curl_allowed_summary(config: CommandPolicy) -> str:
    """Render what curl invocations are allowed, for agent-facing messages.

    Generated from the live policy so it never drifts from what the handler
    actually enforces.
    """
    targets = config.get("targets", [])
    tdesc = "; ".join(_target_description(t) for t in targets) or "(none configured)"

    shape: list[str] = []
    require_first = config.get("require_first")
    if require_first:
        shape.append(f"start with {require_first}")
    required = config.get("require_flags", [])
    if required:
        shape.append("include " + " ".join(required))
    if "--noproxy" in required:
        shape.append("--noproxy value must be the literal '*'")
    shape.append("exactly one URL")

    netrc = config.get("netrc_file_paths") or list(_DEFAULT_NETRC_PATHS)
    return (
        "Allowed curl: a single GET to one of these targets: "
        f"{tdesc}. Invocation must {', '.join(shape)}. "
        f"--netrc-file only accepts {', '.join(netrc)} (pipe credentials in); "
        "--data-urlencode only literal values (no '@file'); "
        "URL globbing is disabled and arguments are treated as literal values."
    )


def _curl_consume_value(
    flag: str, value: str, config: CommandPolicy
) -> tuple[bool, str]:
    """Validate the value that follows a value-taking curl flag."""
    if len(value) > MAX_POLICY_TOKEN_LENGTH:
        return (
            False,
            f"Flag '{flag}' value is {len(value)} characters; the maximum is {MAX_POLICY_TOKEN_LENGTH}",
        )
    rule = next(
        (
            candidate
            for candidate in config.get("flags", [])
            if candidate["flag"] == flag
        ),
        None,
    )
    compiled_pattern = config.get("_compiled_flags", {}).get(flag)
    if rule is None or compiled_pattern is None:
        return False, f"Flag '{flag}' is not declared as value-taking"
    if compiled_pattern.fullmatch(value) is None:
        return (
            False,
            f"Flag '{flag}' received value {value!r}, which does not match value_pattern {rule['value_pattern']!r}; matching is case-sensitive and applies to the complete value",
        )

    if flag == "--url":
        return _curl_url_allowed(value, config.get("targets", []))
    if flag in ("--max-time", "--connect-timeout"):
        try:
            seconds = float(value)
        except ValueError:
            return False, f"Flag '{flag}' requires a numeric value"
        if seconds <= 0:
            return False, f"Flag '{flag}' requires a positive value"
        return True, "OK"
    if flag == "--data-urlencode":
        # Permit only literal 'name=content'/'content' forms; reject @file/@-
        # which would read a local file or stdin and send it to the server.
        if _data_urlencode_reads_file(value):
            return False, "--data-urlencode file-input form ('@...') is not allowed"
        return True, "OK"
    if flag == "--netrc-file":
        # Restrict to configured paths so the agent cannot point curl at an
        # arbitrary credentials file readable by the SSH account. The default
        # allows only /dev/stdin, i.e. credentials piped in, never a disk path.
        allowed_paths = config.get("netrc_file_paths") or list(_DEFAULT_NETRC_PATHS)
        if value not in allowed_paths:
            return (
                False,
                f"--netrc-file path '{value}' is not allowed (allowed: {', '.join(allowed_paths)})",
            )
        return True, "OK"
    # --noproxy and any other value-taking flag: value is unconstrained.
    return True, "OK"


def _validate_curl(
    arguments: list[str], config: CommandPolicy, cmd_name: str
) -> tuple[bool, str]:
    """Value-aware curl validator (deny-by-default). See ADR-003."""
    allowed_flags = set(config.get("_compiled_flags", {}))
    require_first = config.get("require_first")
    required_flags = config.get("require_flags", [])
    single_request = config.get("single_request", True)
    targets = config.get("targets", [])

    # Every rejection tells the agent what IS allowed, so it can self-correct.
    summary = _curl_allowed_summary(config)

    def reject(msg: str) -> tuple[bool, str]:
        return (
            False,
            f"Command '{cmd_name}' was rejected and not executed: {msg}. {summary}",
        )

    if not targets:
        return reject(f"Command '{cmd_name}' has no allowed targets configured")

    # --disable only suppresses default curl config when it is the FIRST argument;
    # requiring mere presence (as generic whitelist mode does) is not enough.
    if require_first and (not arguments or arguments[0] != require_first):
        return reject(f"{cmd_name} requires {require_first} as the first argument")

    seen_flags: set[str] = set()
    flag_values: dict[str, str] = {}
    url_count = 0
    pending_value_flag: str | None = None

    for token in arguments:
        if len(token) > MAX_POLICY_TOKEN_LENGTH:
            return reject(
                f"argument token is {len(token)} characters; the maximum is {MAX_POLICY_TOKEN_LENGTH}"
            )

        if pending_value_flag is not None:
            ok, msg = _curl_consume_value(pending_value_flag, token, config)
            if not ok:
                return reject(msg)
            flag_values[pending_value_flag] = token
            if pending_value_flag == "--url":
                url_count += 1
            pending_value_flag = None
            continue

        if token.startswith("-"):
            flag = token
            inline_value: str | None = None
            if token.startswith("--") and "=" in token:
                flag, inline_value = token.split("=", 1)
            if flag not in allowed_flags and flag != require_first:
                return reject(f"Flag '{flag}' is not allowed for {cmd_name}")
            seen_flags.add(flag)
            if flag in _CURL_VALUE_FLAGS:
                if inline_value is not None:
                    ok, msg = _curl_consume_value(flag, inline_value, config)
                    if not ok:
                        return reject(msg)
                    flag_values[flag] = inline_value
                    if flag == "--url":
                        url_count += 1
                else:
                    pending_value_flag = flag
            elif inline_value is not None:
                return reject(f"Flag '{flag}' does not take a value for {cmd_name}")
        else:
            ok, msg = _curl_url_allowed(token, targets)
            if not ok:
                return reject(msg)
            url_count += 1

    if pending_value_flag is not None:
        return reject(
            f"Flag '{pending_value_flag}' is missing its value for {cmd_name}"
        )

    for req in required_flags:
        if req not in seen_flags:
            return reject(f"{cmd_name} requires the {req} flag")

    # --noproxy must disable the proxy for all hosts, otherwise a loopback URL
    # could still be routed off-box via proxy environment variables.
    if "--noproxy" in required_flags and flag_values.get("--noproxy") != "*":
        return reject(
            "--noproxy value must be '*' (quote it) to keep requests on the host"
        )

    if url_count == 0:
        return reject(f"{cmd_name} requires a URL from the allowed target list")
    if single_request and url_count > 1:
        return reject(f"{cmd_name} allows only a single URL")

    return True, "OK"


def _docker_allowed_summary() -> str:
    """Describe the policy-validated docker exec form."""
    return (
        "When a diagnostic command is unavailable on the host, use docker ps "
        "to identify the relevant container, then use this allowed syntax: "
        "docker exec <container> <command> "
        "[arguments...]. The container may be any non-option name or ID reference "
        "accepted by Docker; Docker exec options and nested Docker commands are "
        "not allowed; the inner command and arguments must pass their effective "
        "command policy."
    )


def _validate_docker(
    arguments: list[str], config: CommandPolicy, cmd_name: str
) -> tuple[bool, str]:
    """Validate Docker inspection or one policy-validated container command."""
    if not arguments or arguments[0] != "exec":
        return _validate_generic_command(arguments, config, cmd_name)

    def reject(message: str) -> tuple[bool, str]:
        return (
            False,
            (
                f"Command '{cmd_name}' was rejected and not executed: {message}. "
                f"{_docker_allowed_summary()}"
            ),
        )

    if len(arguments) < 2:
        return reject("docker exec requires a container")
    container = arguments[1]
    if not container:
        return reject("docker exec requires a non-empty container")
    if container.startswith("-"):
        return reject(f"Docker exec options are not allowed: {container!r}")
    if len(arguments) < 3:
        return reject("docker exec requires an inner command")

    inner_command = arguments[2]
    inner_arguments = arguments[3:]
    safe, message = _validate_command_stage(
        inner_command,
        inner_arguments,
        allow_docker_handler=False,
    )
    if not safe:
        return reject(
            f"inner command {inner_command!r} failed policy validation: {message}"
        )
    return True, "OK"


CommandHandler = Callable[[list[str], CommandPolicy, str], tuple[bool, str]]

COMMAND_HANDLERS: dict[str, CommandHandler] = {
    "curl": _validate_curl,
    "docker": _validate_docker,
}


def _ensure_compiled_policy(cmd_name: str, config: CommandPolicy) -> CommandPolicy:
    if "_compiled_flags" in config:
        return config
    return _normalize_command_policy(cmd_name, config, "runtime policy")


def _flag_rules_by_name(config: CommandPolicy) -> dict[str, FlagPolicy]:
    return {flag["flag"]: flag for flag in config.get("flags", [])}


def _generic_rejection(cmd_name: str, message: str) -> tuple[bool, str]:
    return (
        False,
        f"Command '{cmd_name}' was rejected and not executed: {message}",
    )


def _validate_flag_value(
    cmd_name: str,
    flag: str,
    value: str,
    rule: FlagPolicy,
    compiled_pattern: re.Pattern[str],
) -> tuple[bool, str]:
    if len(value) > MAX_POLICY_TOKEN_LENGTH:
        return _generic_rejection(
            cmd_name,
            f"value for flag '{flag}' is {len(value)} characters; the maximum is {MAX_POLICY_TOKEN_LENGTH}",
        )
    if compiled_pattern.fullmatch(value) is None:
        return _generic_rejection(
            cmd_name,
            f"flag '{flag}' received value {value!r}, which does not match value_pattern {rule['value_pattern']!r}; matching is case-sensitive and applies to the complete value",
        )
    return True, "OK"


def _validate_positional_arguments(
    cmd_name: str, positionals: list[str], config: CommandPolicy
) -> tuple[bool, str]:
    for token in positionals:
        if len(token) > MAX_POLICY_TOKEN_LENGTH:
            return _generic_rejection(
                cmd_name,
                f"positional token is {len(token)} characters; the maximum is {MAX_POLICY_TOKEN_LENGTH}",
            )

    compiled_variants = config.get("_compiled_positional_variants")
    if compiled_variants is None:
        return True, "OK"

    for fixed_patterns, rest_pattern, min_rest, max_rest in compiled_variants:
        fixed_count = len(fixed_patterns)
        if rest_pattern is None:
            if len(positionals) != fixed_count:
                continue
        else:
            rest_count = len(positionals) - fixed_count
            if rest_count < min_rest or rest_count > max_rest:
                continue

        if any(
            pattern.fullmatch(positionals[index]) is None
            for index, pattern in enumerate(fixed_patterns)
        ):
            continue
        if rest_pattern is not None and any(
            rest_pattern.fullmatch(token) is None for token in positionals[fixed_count:]
        ):
            continue
        return True, "OK"

    return _generic_rejection(
        cmd_name,
        f"positional arguments {positionals!r} do not match any positional_variants rule; matching is case-sensitive and applies to each complete token",
    )


def _validate_generic_command(
    arguments: list[str], config: CommandPolicy, cmd_name: str
) -> tuple[bool, str]:
    mode = config.get("mode", "permissive")
    rules = _flag_rules_by_name(config)
    compiled_flags = config.get("_compiled_flags", {})
    allows_bundling = config.get("allows_flag_bundling", False)
    required_flags = config.get("require_flags", [])
    seen_flags: set[str] = set()
    positionals: list[str] = []
    options_ended = False
    index = 0

    def accept_flag(
        flag: str, value: str | None, value_is_inline: bool
    ) -> tuple[bool, str]:
        if mode == "blacklist":
            return _generic_rejection(cmd_name, f"flag '{flag}' is blocked")

        rule = rules[flag]
        compiled_pattern = compiled_flags[flag]
        if compiled_pattern is None:
            if value_is_inline:
                return _generic_rejection(
                    cmd_name,
                    f"flag '{flag}' accepts no value; use '{flag}' without an assignment",
                )
            seen_flags.add(flag)
            return True, "OK"

        if value is None:
            return _generic_rejection(
                cmd_name,
                f"flag '{flag}' requires exactly one value matching value_pattern {rule['value_pattern']!r}",
            )
        valid, reason = _validate_flag_value(
            cmd_name, flag, value, rule, compiled_pattern
        )
        if valid:
            seen_flags.add(flag)
        return valid, reason

    while index < len(arguments):
        token = arguments[index]
        if options_ended:
            positionals.append(token)
            index += 1
            continue
        if token == "--":
            options_ended = True
            index += 1
            continue
        if not token.startswith("-") or token == "-":
            positionals.append(token)
            index += 1
            continue

        if token in rules:
            compiled_pattern = compiled_flags[token]
            value: str | None = None
            if compiled_pattern is not None:
                if index + 1 >= len(arguments):
                    return accept_flag(token, None, False)
                index += 1
                value = arguments[index]
            valid, reason = accept_flag(token, value, False)
            if not valid:
                return valid, reason
            index += 1
            continue

        if token.startswith("--") and "=" in token:
            flag, value = token.split("=", 1)
            if flag in rules:
                valid, reason = accept_flag(flag, value, True)
                if not valid:
                    return valid, reason
                index += 1
                continue

        short_flag = token[:2]
        if len(token) > 2 and not token.startswith("--"):
            short_pattern = compiled_flags.get(short_flag)
            if short_flag in rules and short_pattern is not None:
                valid, reason = accept_flag(short_flag, token[2:], True)
                if not valid:
                    return valid, reason
                index += 1
                continue
            if mode == "blacklist" and short_flag in rules:
                return _generic_rejection(
                    cmd_name,
                    f"token '{token}' starts with blocked short flag '{short_flag}'",
                )

            if allows_bundling:
                if mode == "blacklist":
                    for character in token[1:]:
                        bundled_flag = f"-{character}"
                        if bundled_flag in rules:
                            return _generic_rejection(
                                cmd_name,
                                f"token '{token}' contains blocked bundled flag '{bundled_flag}'",
                            )
                    index += 1
                    continue

                bundle_index = 1
                bundle_valid = True
                while bundle_index < len(token):
                    bundled_flag = f"-{token[bundle_index]}"
                    if bundled_flag not in rules:
                        bundle_valid = False
                        break
                    bundled_pattern = compiled_flags[bundled_flag]
                    if bundled_pattern is None:
                        valid, reason = accept_flag(bundled_flag, None, False)
                        if not valid:
                            return valid, reason
                        bundle_index += 1
                        continue

                    attached_value = token[bundle_index + 1 :]
                    if attached_value:
                        valid, reason = accept_flag(bundled_flag, attached_value, True)
                    elif index + 1 < len(arguments):
                        index += 1
                        valid, reason = accept_flag(
                            bundled_flag, arguments[index], False
                        )
                    else:
                        valid, reason = accept_flag(bundled_flag, None, False)
                    if not valid:
                        return valid, reason
                    bundle_index = len(token)
                if bundle_valid:
                    index += 1
                    continue

        if mode == "whitelist":
            return _generic_rejection(cmd_name, f"flag syntax '{token}' is not allowed")

        # Permissive and blacklist modes allow undeclared flags. Their values
        # cannot be distinguished from positionals, so positional_variants is
        # deliberately forbidden for these modes.
        index += 1

    for required_flag in required_flags:
        if required_flag not in seen_flags:
            return _generic_rejection(
                cmd_name, f"required flag '{required_flag}' is missing"
            )

    return _validate_positional_arguments(cmd_name, positionals, config)


def _validate_command_stage(
    cmd_name: str,
    arguments: list[str],
    *,
    allow_docker_handler: bool = True,
) -> tuple[bool, str]:
    """Validate one command stage against the complete effective policy."""
    if cmd_name not in COMMAND_POLICIES:
        return (
            False,
            f"Command '{cmd_name}' was rejected and not executed because it is not allowed in safe mode. Safe mode allows {len(COMMAND_POLICIES)} read-only commands.",
        )

    try:
        config = _ensure_compiled_policy(cmd_name, COMMAND_POLICIES[cmd_name])
    except ValueError as error:
        return False, str(error)

    handler_name = config.get("handler")
    if handler_name:
        if handler_name == "docker" and not allow_docker_handler:
            return (
                False,
                f"Command '{cmd_name}' was rejected and not executed because nested Docker handler invocation is not allowed",
            )
        handler = COMMAND_HANDLERS.get(handler_name)
        if handler is None:
            return (
                False,
                f"Command '{cmd_name}' uses unknown handler '{handler_name}'",
            )
        return handler(arguments, config, cmd_name)

    return _validate_generic_command(arguments, config, cmd_name)


def _pipeline_rejection(message: str) -> str:
    return f"Command pipeline was rejected and not executed: {message}"


def _contains_nul(value: str) -> bool:
    return "\x00" in value


def _escape_for_log(value: str) -> str:
    return "".join(
        f"\\x{ord(character):02x}"
        if ord(character) < 32 or ord(character) == 127
        else character
        for character in value
    )


def _normalize_pipeline(pipeline: object) -> tuple[list[CommandStage] | None, str]:
    if not isinstance(pipeline, list):
        return None, _pipeline_rejection("pipeline must be a JSON array")
    if not pipeline:
        return None, _pipeline_rejection("pipeline must contain at least one stage")
    if len(pipeline) > MAX_PIPELINE_STAGES:
        return None, _pipeline_rejection(
            f"pipeline contains {len(pipeline)} stages; the maximum is {MAX_PIPELINE_STAGES}"
        )

    normalized: list[CommandStage] = []
    required_fields = {"command", "arguments"}
    for stage_number, raw_stage in enumerate(pipeline, start=1):
        if not isinstance(raw_stage, dict):
            return None, _pipeline_rejection(
                f"stage {stage_number} must be an object containing command and arguments"
            )
        stage_data: dict[object, object] = cast(dict[object, object], raw_stage)
        actual_fields = set(stage_data)
        if actual_fields != required_fields:
            missing = sorted(required_fields - actual_fields)
            unknown = sorted(str(field) for field in actual_fields - required_fields)
            details: list[str] = []
            if missing:
                details.append(f"missing fields: {', '.join(missing)}")
            if unknown:
                details.append(f"unknown fields: {', '.join(unknown)}")
            return None, _pipeline_rejection(
                f"stage {stage_number} must contain exactly command and arguments ({'; '.join(details)})"
            )

        raw_command: object = stage_data["command"]
        raw_arguments: object = stage_data["arguments"]
        if not isinstance(raw_command, str) or not raw_command:
            return None, _pipeline_rejection(
                f"stage {stage_number} command must be a non-empty string"
            )
        if len(raw_command) > MAX_POLICY_TOKEN_LENGTH:
            return None, _pipeline_rejection(
                f"stage {stage_number} command is {len(raw_command)} characters; the maximum is {MAX_POLICY_TOKEN_LENGTH}"
            )
        if _contains_nul(raw_command):
            return None, _pipeline_rejection(
                f"stage {stage_number} command must not contain NUL characters"
            )
        if not isinstance(raw_arguments, list):
            return None, _pipeline_rejection(
                f"stage {stage_number} arguments must be a JSON array of strings"
            )
        argument_values: list[object] = cast(list[object], raw_arguments)
        if len(argument_values) > MAX_ARGUMENTS_PER_STAGE:
            return None, _pipeline_rejection(
                f"stage {stage_number} contains {len(argument_values)} arguments; the maximum is {MAX_ARGUMENTS_PER_STAGE}"
            )

        arguments: list[str] = []
        for argument_number, raw_argument in enumerate(argument_values, start=1):
            if not isinstance(raw_argument, str):
                return None, _pipeline_rejection(
                    f"stage {stage_number} argument {argument_number} must be a string"
                )
            if len(raw_argument) > MAX_POLICY_TOKEN_LENGTH:
                return None, _pipeline_rejection(
                    f"stage {stage_number} argument {argument_number} is {len(raw_argument)} characters; the maximum is {MAX_POLICY_TOKEN_LENGTH}"
                )
            if _contains_nul(raw_argument):
                return None, _pipeline_rejection(
                    f"stage {stage_number} argument {argument_number} must not contain NUL characters"
                )
            arguments.append(raw_argument)

        normalized.append({"command": raw_command, "arguments": arguments})

    rendered = render_pipeline(normalized)
    rendered_bytes = len(rendered.encode("utf-8"))
    if rendered_bytes > MAX_RENDERED_PIPELINE_LENGTH:
        return None, _pipeline_rejection(
            f"rendered pipeline is {rendered_bytes} UTF-8 bytes; the maximum is {MAX_RENDERED_PIPELINE_LENGTH}"
        )
    return normalized, "OK"


def render_pipeline(pipeline: list[CommandStage]) -> str:
    """Render validated structured stages as one safely quoted shell pipeline."""
    return " | ".join(
        shlex.join([stage["command"], *stage["arguments"]]) for stage in pipeline
    )


def _validate_normalized_pipeline(pipeline: list[CommandStage]) -> tuple[bool, str]:
    for stage_number, stage in enumerate(pipeline, start=1):
        cmd_name = stage["command"]
        arguments = stage["arguments"]
        safe, message = _validate_command_stage(cmd_name, arguments)
        if not safe:
            return False, f"Pipeline stage {stage_number}: {message}"

    return True, "OK"


def validate_pipeline(pipeline: object) -> tuple[bool, str]:
    """Validate a structured command pipeline without executing it."""
    normalized, reason = _normalize_pipeline(pipeline)
    if normalized is None:
        return False, reason
    return _validate_normalized_pipeline(normalized)


class _PresentedHostKeyObserver(asyncssh.SSHClient):
    """Capture an untrusted presented key so errors can include a safe fingerprint."""

    def __init__(self) -> None:
        self.presented_key: asyncssh.SSHKey | None = None

    def validate_host_public_key(
        self,
        host: str,
        addr: str,
        port: int,
        key: asyncssh.SSHKey,
    ) -> bool:
        del host, addr, port
        self.presented_key = key
        return False


def _windows_agent_path() -> str | None:
    """Select the native Windows OpenSSH agent when no path is configured."""
    if platform.system() == "Windows" and not os.getenv("SSH_AUTH_SOCK"):
        return WINDOWS_OPENSSH_AGENT_PIPE
    return None


def _host_key_failure_message(
    host_alias: str,
    error: asyncssh.HostKeyNotVerifiable,
    observer: _PresentedHostKeyObserver,
) -> str:
    """Translate host-key failures without returning raw transport details."""
    raw_reason: object = getattr(error, "reason", "")
    reason = raw_reason.casefold() if isinstance(raw_reason, str) else ""
    if "revoked" in reason:
        failure = "is revoked"
    elif "not trusted" in reason:
        failure = "is unknown or changed"
    else:
        failure = "could not be verified"

    key_details = ""
    if observer.presented_key is not None:
        key_type = observer.presented_key.get_algorithm()
        fingerprint = observer.presented_key.get_fingerprint("sha256")
        key_details = f" (type {key_type}, fingerprint {fingerprint})"

    return (
        f"SSH host key for '{host_alias}' {failure}{key_details}. "
        f"Verification uses {KNOWN_HOSTS_PATH}. Run `ssh {host_alias}` in a terminal "
        "and approve the key only after verifying its fingerprint."
    )


def _validate_ssh_host(host: str) -> None:
    """Reject host values which are unsafe to place in diagnostics and pool keys."""
    if (
        not host
        or len(host) > MAX_SSH_ALIAS_LENGTH
        or any(not character.isprintable() or character.isspace() for character in host)
    ):
        raise ValueError(
            "SSH host must be a non-empty hostname, address, or configured alias "
            f"of at most {MAX_SSH_ALIAS_LENGTH} characters without whitespace or "
            "control characters"
        )


def _validate_known_hosts_file() -> None:
    """Read the explicit trust store before each new connection."""
    if not KNOWN_HOSTS_PATH.is_file():
        raise ValueError(
            f"SSH known-hosts file not found at {KNOWN_HOSTS_PATH}. "
            "Run `ssh <alias>` in a terminal to verify and add the host key."
        )
    try:
        asyncssh.read_known_hosts(str(KNOWN_HOSTS_PATH))
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError(
            f"SSH known-hosts file at {KNOWN_HOSTS_PATH} is malformed or unreadable"
        ) from error


def _build_connection_options(host_alias: str) -> asyncssh.SSHClientConnectionOptions:
    """Load AsyncSSH config and apply bounded keepalive defaults."""
    options = asyncssh.SSHClientConnectionOptions(host=host_alias)
    configured_interval: object = options.config.get("ServerAliveInterval")
    raw_interval: object = options.keepalive_interval
    keepalive_interval = (
        float(raw_interval)
        if configured_interval is not None and isinstance(raw_interval, (int, float))
        else DEFAULT_KEEPALIVE_SECONDS
    )
    return asyncssh.SSHClientConnectionOptions(
        options=options,
        keepalive_interval=keepalive_interval,
        keepalive_count_max=KEEPALIVE_COUNT_MAX,
    )


async def _close_ssh_connection(
    host_alias: str,
    connection: asyncssh.SSHClientConnection,
) -> None:
    """Close one pooled connection and wait for local cleanup."""
    connection.close()
    try:
        await connection.wait_closed()
    except Exception as error:  # noqa: BLE001 -- shutdown must continue for other hosts
        logger.warning(
            f"{host_alias}: connection cleanup failed: {type(error).__name__}"
        )


async def _evict_ssh_connection(
    host_alias: str,
    connection: asyncssh.SSHClientConnection,
) -> None:
    """Evict and close a connection only if it is still the pooled instance."""
    lock = ssh_connection_locks.setdefault(host_alias, asyncio.Lock())
    async with lock:
        if ssh_connections.get(host_alias) is connection:
            ssh_connections.pop(host_alias, None)
            await _close_ssh_connection(host_alias, connection)
            logger.info(f"{host_alias}: connection evicted")


async def close_ssh_connections() -> None:
    """Close every pooled connection; repeated calls are safe."""
    pooled = list(ssh_connections.items())
    ssh_connections.clear()
    if pooled:
        logger.info(
            f"SSH connection pool shutdown: closing {len(pooled)} connection(s)"
        )
        await asyncio.gather(
            *(
                _close_ssh_connection(host_alias, connection)
                for host_alias, connection in pooled
            )
        )
        logger.info("SSH connection pool shutdown complete")
    ssh_connection_locks.clear()


async def get_ssh_connection(host_alias: str) -> asyncssh.SSHClientConnection:
    """Get or create the single pooled AsyncSSH connection for a host."""
    _validate_ssh_host(host_alias)
    lock = ssh_connection_locks.setdefault(host_alias, asyncio.Lock())
    async with lock:
        existing = ssh_connections.get(host_alias)
        if existing is not None and not existing.is_closed():
            logger.info(f"{host_alias}: connection reused")
            return existing
        if existing is not None:
            ssh_connections.pop(host_alias, None)
            await _close_ssh_connection(host_alias, existing)
            logger.info(f"{host_alias}: closed connection removed from pool")

        _validate_known_hosts_file()
        observer = _PresentedHostKeyObserver()

        def client_factory() -> _PresentedHostKeyObserver:
            return observer

        logger.debug(f"{host_alias}: attempting one AsyncSSH connection")
        try:
            options = _build_connection_options(host_alias)
            agent_path = _windows_agent_path()
            if agent_path is None:
                connection = await asyncssh.connect(
                    host_alias,
                    options=options,
                    known_hosts=str(KNOWN_HOSTS_PATH),
                    client_factory=client_factory,
                )
            else:
                connection = await asyncssh.connect(
                    host_alias,
                    options=options,
                    known_hosts=str(KNOWN_HOSTS_PATH),
                    agent_path=agent_path,
                    client_factory=client_factory,
                )
        except asyncssh.HostKeyNotVerifiable as error:
            message = _host_key_failure_message(host_alias, error, observer)
            logger.warning(message)
            raise ValueError(message) from error
        except asyncssh.PermissionDenied as error:
            message = (
                f"SSH authentication failed for '{host_alias}'. Check the configured "
                "IdentityFile, loaded SSH-agent keys, and whether a key requires an "
                "interactive passphrase."
            )
            logger.warning(message)
            raise ValueError(message) from error
        except asyncssh.KeyImportError as error:
            message = (
                f"SSH key loading failed for '{host_alias}'. Check configured key files; "
                "encrypted keys must already be available through a non-interactive agent."
            )
            logger.warning(message)
            raise ValueError(message) from error
        except asyncssh.ConfigParseError as error:
            message = f"SSH configuration for '{host_alias}' is invalid"
            logger.warning(message)
            raise ValueError(message) from error
        except TimeoutError as error:
            message = f"SSH connection to '{host_alias}' timed out"
            logger.warning(message)
            raise TimeoutError(message) from error
        except (asyncssh.Error, OSError) as error:
            message = f"SSH connection to '{host_alias}' failed: {type(error).__name__}"
            logger.warning(message)
            raise ConnectionError(message) from error

        ssh_connections[host_alias] = connection
        username: object = connection.get_extra_info("username")
        identity = username if isinstance(username, str) else "configured user"
        logger.info(f"{identity}@{host_alias}: connection established")
        return connection


async def _read_bounded_stream(
    stream: asyncssh.SSHReader[bytes],
    limit_reached: asyncio.Event,
) -> tuple[bytes, bool]:
    """Read one process stream without retaining more than the response limit."""
    output = bytearray()
    while True:
        remaining = MAX_RESPONSE_BYTES - len(output)
        read_size = min(STREAM_READ_BYTES, remaining + 1)
        raw_chunk: object = await stream.read(read_size)
        if not isinstance(raw_chunk, bytes):
            raise TypeError("AsyncSSH byte stream returned non-byte output")
        if not raw_chunk:
            return bytes(output), False
        if len(raw_chunk) > remaining:
            output.extend(raw_chunk[:remaining])
            limit_reached.set()
            return bytes(output), True
        output.extend(raw_chunk)


async def _wait_for_process_or_limit(
    process: asyncssh.SSHClientProcess[bytes],
    limit_reached: asyncio.Event,
) -> None:
    """Close the process as soon as either output stream exceeds its limit."""
    process_closed = asyncio.create_task(process.wait_closed())
    output_limited = asyncio.create_task(limit_reached.wait())
    try:
        done, _ = await asyncio.wait(
            {process_closed, output_limited},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if output_limited in done and limit_reached.is_set():
            process.close()
        await process_closed
    finally:
        for task in (process_closed, output_limited):
            if not task.done():
                task.cancel()
        await asyncio.gather(process_closed, output_limited, return_exceptions=True)


async def _close_ssh_process(process: asyncssh.SSHClientProcess[bytes]) -> None:
    """Close a command channel and bound local cleanup time."""
    process.close()
    try:
        await asyncio.wait_for(
            process.wait_closed(),
            timeout=PROCESS_CLEANUP_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        logger.warning("SSH process cleanup timed out")
    except (asyncssh.Error, OSError) as error:
        logger.warning(f"SSH process cleanup failed: {type(error).__name__}")


async def _run_bounded_process(
    client: asyncssh.SSHClientConnection,
    rendered: str,
) -> tuple[bytes, bytes, int | None, bool, bool]:
    """Run one process and consume stdout and stderr concurrently."""
    process: asyncssh.SSHClientProcess[bytes] | None = None
    try:
        process = await client.create_process(
            rendered,
            encoding=None,
            stdin=asyncssh.DEVNULL,
        )
        limit_reached = asyncio.Event()
        stdout_task = asyncio.create_task(
            _read_bounded_stream(process.stdout, limit_reached)
        )
        stderr_task = asyncio.create_task(
            _read_bounded_stream(process.stderr, limit_reached)
        )
        process_task = asyncio.create_task(
            _wait_for_process_or_limit(process, limit_reached)
        )
        try:
            (
                (stdout_bytes, stdout_truncated),
                (
                    stderr_bytes,
                    stderr_truncated,
                ),
                _,
            ) = await asyncio.gather(stdout_task, stderr_task, process_task)
        finally:
            for task in (stdout_task, stderr_task, process_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(
                stdout_task,
                stderr_task,
                process_task,
                return_exceptions=True,
            )

        raw_exit_status: object = process.exit_status
        exit_code = (
            None
            if stdout_truncated or stderr_truncated
            else raw_exit_status
            if isinstance(raw_exit_status, int)
            else -1
        )
        return (
            stdout_bytes,
            stderr_bytes,
            exit_code,
            stdout_truncated,
            stderr_truncated,
        )
    except asyncio.CancelledError:
        if process is not None:
            await _close_ssh_process(process)
        raise
    except Exception:
        if process is not None:
            await _close_ssh_process(process)
        raise


async def execute_ssh_command(
    host: str, pipeline: list[CommandStage]
) -> tuple[str, str, int | None]:
    """
    Execute a structured command pipeline on a remote host.
    Returns (stdout, stderr, exit_code), where exit_code is unavailable after
    output truncation.
    """
    normalized, error_msg = _normalize_pipeline(pipeline)
    if normalized is None:
        logger.warning(f"{host}: REJECTED - {pipeline!r} - Reason: {error_msg}")
        raise ValueError(f"Command pipeline rejected: {error_msg}")

    is_safe, error_msg = _validate_normalized_pipeline(normalized)
    if not is_safe:
        rendered = render_pipeline(normalized)
        logger.warning(
            f"{host}: REJECTED - {_escape_for_log(rendered)} - Reason: {error_msg}"
        )
        raise ValueError(f"Command pipeline rejected: {error_msg}")

    client = await get_ssh_connection(host)
    raw_username: object = client.get_extra_info("username")
    username = raw_username if isinstance(raw_username, str) else "configured user"

    rendered = render_pipeline(normalized)
    logger.info(f"{username}@{host}: {_escape_for_log(rendered)}")

    try:
        (
            stdout_bytes,
            stderr_bytes,
            exit_code,
            stdout_truncated,
            stderr_truncated,
        ) = await asyncio.wait_for(
            _run_bounded_process(client, rendered),
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except TimeoutError as error:
        if client.is_closed():
            await _evict_ssh_connection(host, client)
        logger.warning(
            f"{username}@{host}: TIMEOUT after {COMMAND_TIMEOUT_SECONDS}s - {_escape_for_log(rendered)}"
        )
        raise TimeoutError(
            f"Command timed out after {COMMAND_TIMEOUT_SECONDS} seconds"
        ) from error
    except asyncio.CancelledError:
        logger.info(f"{username}@{host}: CANCELLED - {_escape_for_log(rendered)}")
        if client.is_closed():
            await _evict_ssh_connection(host, client)
        raise
    except (asyncssh.Error, OSError) as error:
        if client.is_closed():
            await _evict_ssh_connection(host, client)
        message = f"SSH command on '{host}' failed: {type(error).__name__}"
        logger.warning(message)
        raise ConnectionError(message) from error

    stdout_text = stdout_bytes.decode("utf-8", errors="replace")
    stderr_text = stderr_bytes.decode("utf-8", errors="replace")

    limit_kb = MAX_RESPONSE_BYTES // 1024
    if stdout_truncated:
        stdout_text += f"\n\n[truncated - exceeded {limit_kb}KB limit]"
        logger.info(f"{username}@{host}: stdout truncated at {limit_kb}KB")
    if stderr_truncated:
        stderr_text += f"\n\n[truncated - exceeded {limit_kb}KB limit]"
        logger.info(f"{username}@{host}: stderr truncated at {limit_kb}KB")

    if exit_code is None:
        logger.info(f"{username}@{host}: exit_status=unavailable")
    else:
        logger.info(f"{username}@{host}: exit_code={exit_code}")

    return stdout_text, stderr_text, exit_code


async def test_connection(host: str) -> str:
    """Test SSH connection to host."""
    try:
        logger.info(f"{host}: testing connection")
        client = await get_ssh_connection(host)
        if not client.is_closed():
            logger.info(f"{host}: connection test successful")
            return f"Connection to {host} is active"
        logger.warning(f"{host}: connection test failed - connection is closed")
        return f"Connection to {host} is not active"
    except Exception as error:  # noqa: BLE001 -- tool boundary reports all failures
        logger.error(f"{host}: connection test failed - {error}")
        return f"Connection to {host} failed: {error}"


@asynccontextmanager
async def _mcp_lifespan(_: MCPServer[None]) -> AsyncIterator[None]:
    """Close pooled SSH connections when the MCP server stops."""
    try:
        yield None
    finally:
        await close_ssh_connections()


# Create MCP server
mcp: MCPServer[None] = MCPServer("safe-ssh-mcp", lifespan=_mcp_lifespan)

# Tools raise ToolError so the agent sees why a call failed (rejected command,
# timeout, connection error). mcp v2 hides the message of any other exception.


@mcp.tool()
def ssh_list_hosts() -> str:
    """
    List best-effort concrete Host entries found directly in ~/.ssh/config.
    The result can omit included aliases and does not restrict connection targets.
    """
    try:
        hosts = list_ssh_hosts()
    except Exception as e:
        raise ToolError(str(e)) from e
    return "\n".join(hosts)


@mcp.tool()
async def ssh_execute(host: str, pipeline: list[CommandStage]) -> str:
    """
    Execute ordered command stages on a remote host. Use one stage for a single
    command. Each stage has command and arguments fields; do not send shell text.
    Every stage is validated for safety - only read-only operations are allowed.
    curl is restricted to a single GET to allowlisted targets (loopback only by
    default). When a diagnostic command is unavailable on the host and Docker
    support is enabled, use docker ps to identify the relevant container, then use
    docker exec <container> <command> [arguments...]. The inner command must pass
    its effective policy; Docker exec options and nested Docker commands are not
    allowed. A rejected stage replies with the exact allowed pattern, or call
    ssh_describe_validation_rules for the full rules.
    """
    try:
        stdout, stderr, exit_code = await execute_ssh_command(host, pipeline)
    except Exception as e:
        raise ToolError(str(e)) from e

    result = (
        "Exit status: unavailable (command stopped after output limit)\n\n"
        if exit_code is None
        else f"Exit code: {exit_code}\n\n"
    )
    if stdout:
        result += f"STDOUT:\n{stdout}\n"
    if stderr:
        result += f"STDERR:\n{stderr}\n"

    return result


@mcp.tool()
async def ssh_test_connection(host: str) -> str:
    """Test SSH connection to host"""
    return await test_connection(host)


@mcp.tool()
def ssh_list_allowed_commands() -> str:
    """
    List allowed commands and their effective flag and positional syntax as JSON.
    Patterns use case-sensitive full-string matching. Use this before constructing
    a structured pipeline, then use ssh_validate_command for a dry run.
    """
    import json

    result: AllowedCommands = {
        "total_commands": len(COMMAND_POLICIES),
        "pipeline_contract": {
            "parameter": "pipeline",
            "stage_fields": ["command", "arguments"],
            "max_stages": MAX_PIPELINE_STAGES,
            "max_arguments_per_stage": MAX_ARGUMENTS_PER_STAGE,
            "max_token_characters": MAX_POLICY_TOKEN_LENGTH,
            "max_rendered_utf8_bytes": MAX_RENDERED_PIPELINE_LENGTH,
            "single_command_example": [{"command": "uptime", "arguments": []}],
            "pipeline_example": [
                {
                    "command": "journalctl",
                    "arguments": ["-u", "myservice", "-n", "200", "--no-pager"],
                },
                {"command": "grep", "arguments": ["-i", "error"]},
            ],
        },
        "commands": {},
    }

    for cmd_name, stored_config in sorted(COMMAND_POLICIES.items()):
        config = _ensure_compiled_policy(cmd_name, stored_config)
        if "handler" in config:
            handler_name = config["handler"]
            handler_info: CommandInfo = {
                "mode": f"handler:{handler_name}",
                "handler": handler_name,
            }
            if "flags" in config:
                handler_info["allowed_flags"] = config["flags"]
            if "require_flags" in config:
                handler_info["required_flags"] = config["require_flags"]
            if "targets" in config:
                handler_info["targets"] = config["targets"]
            if "positional_variants" in config:
                handler_info["positional_variants"] = config["positional_variants"]
            if handler_name == "docker":
                handler_info["docker_exec"] = {
                    "syntax": "docker exec <container> <command> [arguments...]",
                    "use_when": (
                        "a diagnostic command is unavailable on the host and the relevant executable is available in a running container identified with docker ps"
                    ),
                    "container": (
                        "any non-option container name or ID reference accepted by Docker"
                    ),
                    "docker_options": False,
                    "inner_commands": (
                        "all effective command policies except handler:docker"
                    ),
                }
            handler_info["allows_flag_bundling"] = config.get(
                "allows_flag_bundling", False
            )
            handler_info["pattern_matching"] = "case-sensitive full-string"
            result["commands"][cmd_name] = handler_info
            continue

        cmd_info: CommandInfo = {
            "mode": config.get("mode", "permissive"),
            "allows_flag_bundling": config.get("allows_flag_bundling", False),
            "pattern_matching": "case-sensitive full-string",
        }

        if "flags" in config:
            if config.get("mode", "permissive") == "blacklist":
                cmd_info["blocked_flags"] = config["flags"]
            else:
                cmd_info["allowed_flags"] = config["flags"]

        if "require_flags" in config:
            cmd_info["required_flags"] = config["require_flags"]
        if "positional_variants" in config:
            cmd_info["positional_variants"] = config["positional_variants"]

        result["commands"][cmd_name] = cmd_info

    return json.dumps(result, indent=2)


@mcp.tool()
def ssh_describe_validation_rules() -> str:
    """
    Describe the command validation rules and security restrictions.
    Explains what types of commands and operations are blocked and why.
    """
    rules = f"""SSH MCP Server - Command Validation Rules

THREAT MODEL:
Prevent system MODIFICATION and data EXFILTRATION via network.
Users already have SSH access, so reading files/system info is acceptable.

STRUCTURED PIPELINE INPUT:
- ssh_execute and ssh_validate_command accept a pipeline JSON array.
- Every stage contains exactly command (string) and arguments (array of strings).
- A single command is represented by a one-stage pipeline.
- The server validates every stage, quotes it with shlex.join, and inserts only | between stages.
- Arguments are literal values. Shell operators inside arguments are quoted and cannot add syntax.
- Redirections, command lists, substitutions, expansions, glob syntax, and background execution have no structured representation.
- SSH uses the account's configured remote shell. The exit code is the final stage's exit code.
- Limits: {MAX_PIPELINE_STAGES} stages, {MAX_ARGUMENTS_PER_STAGE} arguments per stage, {MAX_POLICY_TOKEN_LENGTH} characters per token, and {MAX_RENDERED_PIPELINE_LENGTH} rendered UTF-8 bytes.

BLOCKED OPERATIONS:
- File modification commands (rm, mv, cp, touch, mkdir, chmod, chown)
- Network exfiltration commands (wget, ssh, scp, rsync)
- curl to any host except configured allowlisted targets (handler mode)
- Process control (kill, pkill, sudo, su)
- Command execution via flags (find -exec, find -delete)
- Archive extraction (tar -x, unzip without -l) -- creates files
- Any command not declared by the command policy

POLICY PATTERN SEMANTICS:
- Every flag is an object containing flag and value_pattern.
- value_pattern: null means the flag accepts no value.
- A regular-expression value_pattern means the flag requires exactly one value.
- All regular expressions use case-sensitive full-string matching.
- --flag=value and --flag value are equivalent for value-taking long flags.
- -n100 and -n 100 are equivalent when -n has a value_pattern.
- Short-flag bundling is accepted only when allows_flag_bundling is true.
- An exact -- token ends option parsing.
- positional_variants, when present, must match the complete positional sequence.
- Array variants have exact arity; bounded-rest variants limit repeated operands.
- Policies are trusted operator configuration and must not come from remote or untrusted sources.
- Invalid policy schemas and patterns stop server startup.

VALIDATION MODES:
1. PERMISSIVE MODE allows all arguments for commands whose complete grammar is read-only.
2. WHITELIST MODE allows only declared flags and optional positional variants.
3. BLACKLIST MODE allows arguments except specifically blocked dangerous flags.
4. HANDLER MODE uses a command-specific validator for value-sensitive or nested command grammar such as curl and docker exec.

REMOVED COMMANDS (internal exec/write that flag validation cannot catch):
- awk: system() executes commands, print>"file" writes, print|"cmd" pipes
- sed: e command executes shell, w command writes files

ALLOWED COMMAND CATEGORIES (base set, extensible via YAML):
- File operations: ls, cat, pwd, file, stat
- Text processing: grep, head, tail, wc, sort, uniq, cut, tr, diff, comm
- File search: find
- System information: whoami, hostname, uname, date, which
- Disk usage: du, df
- Path manipulation: basename, dirname
- Process inspection: ps, top, free
- System logs: journalctl
- Archive inspection: tar, unzip, zipinfo
- Structured data: jq, xmllint, yq
- Network diagnostics: ping, netstat, ss, iostat, nc
- Network fetch (handler mode): curl, allowlisted targets only
- Container inspection and policy-validated execution: docker
- Security status: ufw, nft, iptables, ip6tables, getenforce, aa-status, auditctl, fail2ban-client (strict read-only forms only)

All command-specific policies are loaded from YAML files in the configured policy directory.
Use ssh_list_allowed_commands to inspect the pipeline contract and each command's
effective value_pattern, positional_variants, required flags, and bundling setting.

STRUCTURED EXAMPLES:
- Single command: [{{"command": "uptime", "arguments": []}}]
- Pipeline: [{{"command": "journalctl", "arguments": ["-u", "myservice", "-n", "200"]}}, {{"command": "grep", "arguments": ["-i", "error"]}}]

For detailed information about specific commands, use ssh_list_allowed_commands.
To test a pipeline before execution, use ssh_validate_command.
"""

    curl_config = COMMAND_POLICIES.get("curl")
    if curl_config and curl_config.get("handler") == "curl":
        rules += f"\nCURL POLICY (live):\n{_curl_allowed_summary(curl_config)}\n"

    docker_config = COMMAND_POLICIES.get("docker")
    if docker_config and docker_config.get("handler") == "docker":
        rules += f"\nDOCKER POLICY (live):\n{_docker_allowed_summary()}\n"

    return rules


@mcp.tool()
def ssh_validate_command(pipeline: list[CommandStage]) -> str:
    """
    Validate structured command stages without executing them (dry-run).
    Use one stage for a single command. Each stage must contain command and arguments.
    """
    normalized, error_msg = _normalize_pipeline(pipeline)
    if normalized is None:
        return f"INVALID: {error_msg}\n\nPipeline: {pipeline!r}\n\nUse ssh_describe_validation_rules for the pipeline contract."

    rendered = render_pipeline(normalized)
    is_safe, error_msg = _validate_normalized_pipeline(normalized)

    if is_safe:
        return f"VALID: Pipeline '{rendered}' will execute successfully."
    else:
        return f"INVALID: {error_msg}\n\nPipeline: {rendered}\n\nUse ssh_describe_validation_rules for more information about validation rules.\nUse ssh_list_allowed_commands to see the pipeline contract and all allowed commands."


def main() -> None:
    """Initialize and run the stdio MCP server."""
    try:
        policy_dir, log_file = initialize_runtime()
    except (OSError, ValueError) as error:
        print(f"safe-ssh-mcp: startup failed: {error}", file=sys.stderr, flush=True)
        raise SystemExit(78) from error

    logger.info("SSH MCP Server starting...")
    logger.info(f"Policy directory: {policy_dir}")
    logger.info(f"Log file: {log_file}")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
