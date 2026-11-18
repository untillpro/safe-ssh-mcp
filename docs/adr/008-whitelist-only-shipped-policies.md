# ADR: Whitelist-only shipped policies

Date: 2026-11-18

## Status

Accepted. Replaces the mode assignment of [ADR 002](002-mvp-command-whitelist.md), which shipped permissive and blacklist policies, and follows from [ADR 007](007-policy-validated-sudo.md).

## Context

Generic policies had three modes. Whitelist accepted only the listed flags. Blacklist accepted every flag except the listed ones. Permissive accepted every flag and was meant for commands with no modifying form.

Every gap found in the shipped policies came from a blacklist or permissive policy:

- `uniq INPUT OUTPUT` wrote a file through an operand, and `file -C` compiled a magic file; both commands were permissive.
- Blacklist policies blocked exact flag names, so abbreviated long options such as `sort --outp=FILE` and `date --se=TIME` passed until the validator learned to reject prefixes of blocked flags.
- Differently spelled aliases still passed, for example `xmllint -o FILE`, `xmllint -shell`, and `yq --inplace`, because a blacklist blocks only the spellings it lists.

Both modes allow whatever they do not name, so each one is only as good as the author's knowledge of every flag, spelling, and operand form in every version of the command. Since [ADR 007](007-policy-validated-sudo.md), policy validation is also the only barrier against modification as root.

Permissive mode is equivalent to a blacklist with no blocked flags. The validator has no permissive-specific logic; the mode only expressed the belief that nothing needed blocking, which is the belief that failed for `uniq` and `file`.

## Decision

- Every shipped policy uses whitelist mode, in the bundled configuration and in configurations that mirror it. A test fails when a shipped policy uses another mode.
- Blacklist mode stays in the engine as an escape hatch for custom configurations. No shipped policy uses it, and it is documented as discouraged.
- Permissive mode is removed. A policy that still declares `mode: permissive` stops startup with an error that names the replacements: list the allowed flags with `mode: whitelist`, or use `mode: blacklist` without flags to keep the previous behaviour.
- A whitelist lists the most useful read-only flags of a command, not its complete grammar. A missing flag is a rejection, not a gap, and is added when a real need appears. The initial lists come from the shipped assessment prompts, the forms the tests already accepted, and the flags recorded in server logs.
- Operands are restricted wherever they can select modifying behaviour. A whitelist policy without `positional_variants` accepts any operands, which is correct only for commands whose operands merely select data to read.

## Rules for writing a whitelist policy

- List flags without a value in `valueless_flags`, an array of names, and flags with a value in `flags`, where each entry carries the pattern its value must match. The array keeps a long whitelist readable; it is shorthand for `flags` entries whose `value_pattern` is `null`.
- Declare a value only for a flag whose command requires one. A flag with an optional value is listed without a value, so its `=VALUE` form is rejected. Declaring such a flag with a value would make the validator consume the next token while the command treats that token as an operand.
- Do not list flags that write files, run programs, change system state, or keep the command running until the timeout.
- List one spelling only when a command accepts several for the same option. Unlisted spellings are rejected.
- Add `positional_variants` when an operand can do more than name data to read.
- Use `require_flags` when a command is only bounded with certain flags.

## Consequences

- The open alias gaps are closed: `xmllint` accepts only two-dash spellings of listed options and rejects URL operands, and `yq` rejects in-place editing and file splitting in every spelling.
- Operand forms are closed as well: `date` accepts only a `+FORMAT` operand, so `date MMDDhhmm` cannot set the clock, and `top` requires batch mode with an iteration count.
- Whitelist mode alone did not make `tar` and `unzip` safe. Both were whitelists already, yet `tar xf FILE` extracted through an operand read as an option cluster, and `unzip FILE` extracted because no flag was required. `tar` now requires `-t` and accepts no operands, and `unzip` requires `-l`.
- Flags that were allowed implicitly and are not on a list are now rejected, for example `ls --color`, `grep --color`, `head -20`, `tail -f`, `journalctl -f`, and `jq --arg`. Agents see the allowed flags through command discovery and in the rejection message; operators add a flag by editing the policy.
- Every form used by the shipped prompts and every pipeline recorded in the available server logs is still accepted.
- Custom configurations that use `mode: permissive` must be edited before the server starts. Custom blacklist policies keep working unchanged.
- The validator keeps rejecting abbreviations of blocked long flags for the remaining blacklist users.
- Whitelist mode does not remove the need for review: an allowed flag or operand can still be wrong, and a flag declared with the wrong arity can let the validator and the command disagree about which token is an operand.

## Reference implementation

- Mode handling and the permissive startup error: [safe_ssh_mcp.py](../../safe_ssh_mcp.py).
- Shipped policies: [core.yaml](../../config/policies/core.yaml) and [system-info.yaml](../../config/policies/system-info.yaml).
- Editor schema: [policy.schema.json](../../config/policies/policy.schema.json).
- Regression coverage, including the whitelist-only guard: [test_dsl.py](../../tests/test_dsl.py).

## References

- [ADR 002: MVP command whitelist](002-mvp-command-whitelist.md)
- [ADR 006: Policy-validated Docker execution](006-policy-validated-docker-exec.md)
- [ADR 007: Policy-validated sudo execution](007-policy-validated-sudo.md)
