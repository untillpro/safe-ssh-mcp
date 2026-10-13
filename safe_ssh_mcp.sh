#!/usr/bin/env bash

set -euo pipefail

usage() {
    printf '%s\n' \
        "Usage: safe_ssh_mcp.sh [--runner auto|uv|pipx] [--] [server arguments...]" \
        "" \
        "Runner selection:" \
        "  auto   Prefer uv, then fall back to pipx with its pip backend (default)." \
        "  uv     Require uv; do not fall back to pipx." \
        "  pipx   Require pipx >= 1.12.0 and use its pip backend."
}

runner="auto"
while (( $# > 0 )); do
    case "$1" in
        --runner)
            if (( $# < 2 )); then
                printf "safe-ssh-mcp: --runner requires auto, uv, or pipx.\n" >&2
                exit 64
            fi
            runner="$2"
            shift 2
            ;;
        --runner=*)
            runner="${1#--runner=}"
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            printf "safe-ssh-mcp: unknown launcher option: %s\n" "$1" >&2
            usage >&2
            exit 64
            ;;
        *)
            break
            ;;
    esac
done

case "$runner" in
    auto|uv|pipx) ;;
    *)
        printf "safe-ssh-mcp: invalid runner '%s'; expected auto, uv, or pipx.\n" "$runner" >&2
        exit 64
        ;;
esac

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
server="$script_dir/safe_ssh_mcp.py"

if [[ ! -f "$server" || ! -r "$server" ]]; then
    printf "safe-ssh-mcp: server script is missing or unreadable: %s\n" "$server" >&2
    exit 66
fi

runner_server="$server"
if command -v cygpath >/dev/null 2>&1; then
    runner_server="$(cygpath -m "$server")"
fi

case "$runner" in
    auto)
        if command -v uv >/dev/null 2>&1; then
            exec uv run --script "$runner_server" "$@"
        fi
        if ! command -v pipx >/dev/null 2>&1; then
            printf "safe-ssh-mcp: neither uv nor pipx >= 1.12.0 is available on PATH.\n" >&2
            exit 127
        fi
        pipx_run_help="$(pipx run --help 2>&1 || true)"
        if [[ "$pipx_run_help" != *"--backend"* ]]; then
            printf "safe-ssh-mcp: pipx is too old; install pipx >= 1.12.0 or install uv.\n" >&2
            exit 127
        fi
        exec pipx run --backend pip "$runner_server" "$@"
        ;;
    uv)
        if ! command -v uv >/dev/null 2>&1; then
            printf "safe-ssh-mcp: selected runner 'uv' is not available on PATH.\n" >&2
            exit 127
        fi
        exec uv run --script "$runner_server" "$@"
        ;;
    pipx)
        if ! command -v pipx >/dev/null 2>&1; then
            printf "safe-ssh-mcp: selected runner 'pipx' is not available on PATH.\n" >&2
            exit 127
        fi
        pipx_run_help="$(pipx run --help 2>&1 || true)"
        if [[ "$pipx_run_help" != *"--backend"* ]]; then
            printf "safe-ssh-mcp: selected runner 'pipx' is too old; install pipx >= 1.12.0.\n" >&2
            exit 127
        fi
        exec pipx run --backend pip "$runner_server" "$@"
        ;;
esac
