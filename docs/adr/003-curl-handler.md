# ADR: Target-allowlisted curl handler

Date: 2026-10-05

## Status

Accepted. Loosens the curl exclusion recorded in [ADR 002](002-mvp-command-whitelist.md).

## Context

ADR-002 excluded `curl` entirely, classing it as network exfiltration, because the three generic validation modes (permissive, whitelist, blacklist) check only flag *names*. curl's risk lives in its argument *values* -- the URL it targets and value-forms like `--data-urlencode @file` -- which flag-name validation cannot see.

Operators may need agents to query a diagnostic HTTP(S) endpoint exposed only on a remote host's loopback interface. When such an endpoint requires authentication, a safe pipeline can produce netrc-formatted credentials from already readable input and pipe them to `curl --netrc-file /dev/stdin`, keeping credential values out of the logged command text.

An earlier `policies/curl.yaml` enabled this with generic whitelist mode, but that approach could not restrict the URL, could not stop local-file reads via `--data-urlencode @file`, and could not restrict which credentials file `--netrc-file` reads. Those gaps were documented in the file header but not enforced.

This ADR adds a fourth validation mode -- a command-specific handler -- and a curl handler built on it, shaped to permit this narrow diagnostic use while constraining dangerous value forms.

## Threat model delta

Unchanged from ADR-002 except for curl:

- Before: `curl` is blocked/excluded.
- After: `curl` is allowed as a single GET to the targets configured in `policies/curl.yaml` -- loopback-only by default -- with the proxy disabled; every other invocation is rejected.

The chosen control is **"stay on the box"**: if curl can only reach a loopback address, there is no off-box network path, so the destination's port and path no longer matter for exfiltration. Loopback also naturally excludes the LAN and the cloud metadata endpoint (link-local `169.254.0.0/16`, which is not loopback). This is why the default policy allows any port and any path on loopback rather than enumerating them.

All other commands, modes, and the overall goal (prevent system modification and data exfiltration; reading is acceptable) are unchanged.

## Decision

Introduce a `handler` policy key. For `handler: curl`, `validate_command` dispatches to the named Python callable in `COMMAND_HANDLERS` and bypasses the generic flag-name modes. The handler returns `(is_safe, reason)` and validates **deny-by-default**: any token it cannot positively classify as safe causes rejection. A later handler may explicitly compose with generic validation, as documented for Docker in [ADR 006](006-policy-validated-docker-exec.md).

Register a `curl` handler (`_validate_curl` in `safe_ssh_mcp.py`) that enforces:

- **URL target allowlist.** Every URL -- whether a bare argument or a `--url` value -- must match a `targets` entry on scheme, host, port, and path. A target `host` may be `loopback` (any IPv4/IPv6 loopback address), an exact name or IP, or a CIDR (e.g. `127.0.0.0/8`); IP/CIDR matching is numeric so encoded-IP tricks resolve to the same address. `port` and `path_prefix` accept `"*"` or may be omitted to mean "any"; an omitted `scheme` allows http + https. Host and scheme are compared case-folded and a trailing dot on the host is stripped.
- **`--disable` first.** It must be the first argument, because it only suppresses default curl config in first position; mere presence (what generic whitelist mode checks) is not enough.
- **`--noproxy '*'` required.** A loopback URL could still be routed off-box via proxy environment variables, so the handler requires `--noproxy` and requires its value to be `*` (disable the proxy for all hosts). This keeps "loopback" actually local.
- **Explicit flag set only.** Only the flags a policy lists are accepted; everything else (including `-X`/method overrides, `--user`, `--basic`, `--netrc`, `-T`, `--form`) is rejected deny-by-default.
- **Value-aware parsing.** Value-taking flags consume their following token so a URL or a required flag cannot be silently misread:
  - `--max-time` / `--connect-timeout`: must be positive numbers.
  - `--data-urlencode`: only the literal `content` / `name=content` forms are accepted. The handler applies curl's own rule (the form is decided by the first `=` or `@`) to reject the `@file` / `@-` input forms, so curl cannot read a local file or stdin into the request body. Literal query parameters are permitted.
  - `--netrc-file`: the path must be in the policy's `netrc_file_paths` (default `/dev/stdin`), so credentials can only be **piped in**, never read from an arbitrary on-disk path such as `/root/.netrc`.
- **Single request.** Exactly one URL; URL globbing (`{}`, `[]`) is rejected (IPv6 host brackets `[::1]` are allowed); embedded credentials (`user:pass@host`) are rejected.
- **No shell escape.** Redirections and expansions (parameter, command/process substitution, arithmetic) are rejected.
- **Self-describing rejections.** Every rejection message appends the allowed curl pattern, rendered from the live policy, so the agent can correct itself. The same summary is served by `ssh_describe_validation_rules`, and `ssh_execute`'s description points there. The summary is generated, not hardcoded, so it cannot drift from what the handler enforces.

A supported credential flow composes curl in a pipeline (`cat ... | jq ... | curl ...`); the handler validates the curl node, and `cat`/`jq` remain ordinary permissive commands. Piping credentials to `--netrc-file /dev/stdin` keeps them out of the logged command text; reading local files is within ADR-002's accepted "reading is acceptable" assumption, and the loopback target keeps the result on-host.

## Rationale

- **Handler, not a richer YAML DSL.** curl's grammar (which flags take values, globbing, config-file flags) is curl-specific. Encoding it as data would reinvent a curl parser in YAML. Keeping the *logic* in Python and the *data* (the target allowlist) in YAML is the clean split.
- **Deny-by-default.** The classic bypass in these validators is "token not recognized, so allowed." The handler inverts that: unrecognized means rejected.
- **URL allowlist is the real control.** Flag checks are secondary; restricting the destination is what prevents exfiltration and reaching internal services.

## What this does NOT guarantee

Documented so the control is not assumed stronger than it is:

- **A reachable loopback service is a trusted sink.** With the default loopback-only policy, any port and path on the box is reachable: a state-changing GET still reaches a local service, and data can still ride in the query string to it. This is bounded to on-host services, which is the point of the loopback control; if a policy widens `host` beyond loopback, narrow `port`/`path_prefix` again.
- **Credentials still reach the service.** `--netrc-file /dev/stdin` keeps the password out of the command log, but curl still sends it to the target. Plain HTTP carries Basic auth as Base64, not encrypted; loopback keeps that on the host. The required `--noproxy '*'` reduces, but the handler does not independently verify, that the request stays on loopback.
- **Name, not address.** The handler validates the host text/address; DNS still resolves at request time on the remote box, so a *name* target does not defend against one that later resolves elsewhere. The default uses loopback IP literals, which avoids this.
- **A parser is one gap from failing open.** Where host-level egress controls (firewall/forced proxy) and a least-privilege SSH account are available, run them underneath as defense in depth: the handler decides request *shape*, the network decides *reach*.

## Configuration

`policies/curl.yaml` ships a loopback-only policy for diagnostic GET access to local HTTP APIs, including credentials piped through `/dev/stdin`, without enumerating endpoint paths. An operator only widens `targets` if a non-loopback destination is genuinely needed.

```yaml
curl:
  handler: curl
  require_first: --disable
  single_request: true
  netrc_file_paths: [/dev/stdin]       # credentials may only be piped in
  targets:
    - {host: loopback}                 # any loopback addr, any port, any path
  require_flags: [--disable, --get, --noproxy]   # --noproxy value must be '*'
  flags:
    - {flag: --disable, value_pattern: null}
    - {flag: --get, value_pattern: null}
    - {flag: --noproxy, value_pattern: '\*'}
    - {flag: --url, value_pattern: '.{1,4096}'}
    - {flag: --data-urlencode, value_pattern: '.{1,4096}'}
    - {flag: --netrc-file, value_pattern: '/dev/stdin'}
    - {flag: --fail, value_pattern: null}
    - {flag: --silent, value_pattern: null}
    - {flag: --show-error, value_pattern: null}
    - {flag: --max-time, value_pattern: '(?:[1-9][0-9]*(?:\.[0-9]+)?|0?\.(?:0*[1-9][0-9]*))'}
    - {flag: --connect-timeout, value_pattern: '(?:[1-9][0-9]*(?:\.[0-9]+)?|0?\.(?:0*[1-9][0-9]*))'}
```

Example accepted command: `curl --disable --get --noproxy '*' --max-time 8 http://127.0.0.1:8080/health`.

## Risks

| Risk                                             | Severity | Mitigation                                                        |
|--------------------------------------------------|----------|-------------------------------------------------------------------|
| State change via GET on a reachable loopback svc | Medium   | Bounded to on-host services; narrow `path_prefix` if host widened |
| Data in query string to a loopback service       | Low      | Stays on the host; only a concern if `host` is widened off-box    |
| Credentials sent to the target over plain HTTP   | Medium   | Loopback keeps it on-host; use TLS where the service supports it  |
| Loopback routed via proxy env vars               | Low      | `--noproxy '*'` is required by the handler                        |
| Handler parser gap fails open                    | Medium   | Deny-by-default; adversarial tests in `tests/test_validation.py`  |
| Operator widens `host` beyond loopback           | High     | Then re-narrow `port`/`path_prefix`; pair with network controls   |

## Consequences

### Positive

- Agents can perform scoped on-host HTTP(S) checks without opening general network egress, and the loopback default needs no per-endpoint maintenance.
- The `handler` seam is reusable for other commands whose risk is value-based.
- Rejections teach the agent the allowed pattern, so it self-corrects without a human round-trip.
- The control and its residual risks are documented rather than implied.

### Negative

- The curl handler is curl-specific code to maintain as curl evolves.
- The validator cannot cover network-layer effects; full assurance still needs host-level controls.
- A broad default (any port/path on loopback) trades tightness for low maintenance; widening `host` off-loopback requires re-narrowing by hand.

## Reference Implementation

- `_validate_curl`, `_curl_url_allowed`, `_host_matches`, `_curl_allowed_summary`, `COMMAND_HANDLERS`, and the `handler` dispatch in `validate_command` -- `safe_ssh_mcp.py`.
- Agent guidance: `ssh_describe_validation_rules` (renders the live summary) and the `ssh_execute` tool description.
- Policy: `policies/curl.yaml`.
- Tests: `CurlHandlerTests` and `CurlLoopbackUsageTests` in `tests/test_validation.py`.

## References

- [ADR 002: MVP command whitelist](002-mvp-command-whitelist.md)
- [ADR 001: Bash command validation for safe operations](001-bashlex.md)
