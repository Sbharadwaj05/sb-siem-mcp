# Changelog

All notable changes to the sb-siem-mcp project.

## [0.2.1] — 2026-10-07

Covers every commit after the 0.2.0 entry was written (`4303981`, 11 June
2026), plus the October 2026 review. Short hashes point to the commits.

### Security

- **RBAC, rate limiting and audit logging enforced on tool calls.** 0.2.0
  shipped the `rbac`, `rate_limiter` and `audit` modules, but they were not
  yet enforced on tool calls: no tool checked a role or a rate limit, and
  the destructive tools wrote no audit record. The `safe_tool` decorator now
  applies RBAC and the per-tool rate limit to every tool, and both
  destructive tools append an audit record when they execute. (`930a242`,
  `f677113`)
- **Output sanitizer wired into `format_json`.** 0.2.0 shipped
  `sanitizer.py`, but tool output did not pass through it. Every tool
  response is now redacted before it reaches the model. The password
  pattern's replacement no longer references a capture group that did not
  exist. (`60adf95`)
- **Confirmation tokens are random.** `secrets.token_hex(16)` replaces the
  first 8 hex characters of a SHA-256 of the action and timestamp.
  (`7595aae`)
- **MCP server binds to localhost by default.** The Dockerfile and
  `docker-compose.yml` set `WAZUH_MCP_HOST=127.0.0.1` (was `0.0.0.0`), and
  `main_sse()` defaults to it. (`b7e3596`) SSE mode itself only starts
  from October 2026, see below; inside the Docker container this bind is
  still not reachable through the published port (Known issues).
- The demo `docker-compose.yml` sets `WAZUH_INSECURE=false`. (`7595aae`)

### Fixed

- Agent queries sent alert field names in `select`, and the sanitizer
  raised on non-string dictionary keys (issues #2 and #3, PR #4). Regression
  tests in `tests/test_output_regressions.py`. (`3bf98ad`)
- Lucene query injection: free-text search is escaped before it is used in
  an indexer `query_string` query. (`08febc0`)
- Multi-manager failover: 0.2.0 created a client for every URL in
  `WAZUH_API_URLS` but only ever used the first. Requests now fall back to
  the other managers on connection errors and timeouts. (`08febc0`)
- `docker-compose.yml` Wazuh version aligned with the README (4.9.0 to
  4.14.5). (`f677113`)

### Changed

- Error hierarchy (`errors.py`), JSON-line logging with request IDs,
  validators called from the tool handlers, `mode` and `compact_output`
  applied across tools, JWT structure and claim checks, TLS client
  certificate support, audit log rotation and a warning when the audit log
  is in the home directory. (`930a242`)
- Project renamed from `wazuh-mcp-server` to `sb-siem-mcp`. (`810945c`)
- Docker base image `python:3.14-slim` (was `3.12-slim`). (`fdb3db0`,
  `1ed0673`)
- CI runs Bandit; the Security Scan workflow runs pip-audit and Bandit as
  non-blocking steps. (`1f999bb`, `acfd39b`)
- The version string is read from `wazuh_mcp.__version__` in the server
  logs and `openapi.py`; `tests/test_version.py` checks the rest.

### Dependencies

- `mcp<2.0.0` (mcp 2.0 renamed `FastMCP` and broke the server import),
  `pydantic>=2.7.0,<3.0.0`, `pydantic-core>=2.18.0,<3.0.0`. Issue #5, PR #6.
  (`8e2e4ee`)
- October 2026: a Dependabot PR (#8) widened the range to `mcp<3.0.0`,
  which installed mcp 2.3.0 and failed the CI import. The range is now
  `mcp>=1.21.1,<2.0.0`. 1.21.1 is the lowest release the test suite passes
  on; earlier FastMCP releases cannot resolve the postponed annotations in
  the tool signatures. Dependabot now ignores major mcp updates.

### Docs

- Tool status wording aligned: no "28/28 operational" or "100%" claims
  remain (R3; started in `5a4a307`).
- MIT `LICENSE` file added (R1). 0.1.0 date corrected to 2026 (R2).
- README "How It Works" and "Production Hardening" sections. (`5900ccb`,
  `7595aae`)

### Added October 2026

- **Fix: confirmation token bound to the confirmed action (R10).** Found in
  review on 6 October 2026. Before this fix, step 2 of
  `wazuh_run_active_response` and `wazuh_agent_command` checked only that
  the token existed and had not expired, then executed the second call's
  agent, command and arguments, and a token issued by one tool worked on
  the other. The token now records the issuing tool, execution is refused
  unless tool, `agent_id`, `command` and `arguments` all match, and a
  rejected attempt consumes the token.
- **Fix: `compact_output` no longer drops requested results (issue #7).**
  `compact()` cut every list to 10 entries, including the `items` of a
  paginated response, while `count` and `has_more` still described the full
  page. A caller asking for `limit=50` got 10 results, and paging by
  `offset += limit` skipped the rest. The envelope's `items` now keep the
  size the caller asked for; lists inside each item are still capped.
  Affects every list tool with `compact_output=true`.
- **Fix: built-in RBAC roles are cumulative.** `ROLE_TOOLS` held only each
  tier's additions, so `soc` could run active responses but not list
  alerts. Roles now include every tool of the tiers below: viewer 14,
  analyst 22, admin 26, soc 28.
- **Fix: active-response `arguments` reach the tool.** The parameter was
  typed `Optional[str]`; FastMCP decodes any JSON string for a parameter
  not typed exactly `str`, so the documented `'["srcip", "10.0.0.50", "-"]'`
  became a list and failed validation. Every active response that needs
  arguments was impossible through MCP. It is now `Optional[List[str]]`, so
  the JSON string and a real array both work.
- **Fix: ID validators reject a trailing newline.** `re.match` with `$`
  accepted `"001\n"`; the seven anchored validators now use `re.fullmatch`.
- **Fix: SSE mode starts.** `main_sse()` passed `host` and `port` to
  `FastMCP.run()`, which does not accept them, and raised `TypeError`.
  They are now set on `mcp.settings`.
- **Fix: Prometheus `/metrics` binds to `WAZUH_MCP_HOST`** (default
  `127.0.0.1`). `prometheus_client` binds every interface unless given an
  address, so in SSE mode `/metrics` listened on `0.0.0.0` while the MCP
  endpoint was on loopback.
- **Fix: active response works on Wazuh 4.x.** Found by running the tools
  against a live Wazuh 4.14.8 manager. The client sent `agent_id` and
  `custom` in the body of `PUT /active-response`, which 4.x rejects with
  "Invalid field found {'agent_id', 'custom'}", so neither destructive
  tool had ever executed anything on 4.x. Agents are now targeted with the
  `agents_list` query parameter. The documented `["srcip", "<ip>", ...]`
  argument is also passed as `alert.data.srcip`, which is where 4.x
  active-response scripts read the IP, after IPv4 validation.
  `wazuh_agent_command` runs `!<script>` (an active-response script on the
  agent, by name). API errors now include Wazuh's per-agent reason, for
  example "The command used is not defined in the configuration." Checked
  live: `!host-deny` with `srcip` 10.0.0.54 wrote `ALL:10.0.0.54` to the
  agent's `/etc/hosts.deny`.
- **Fix: `wazuh_agent_health` counts agree.** `/agents` includes the
  manager as agent 000 and `/agents/summary/status` does not, so
  `total_agents` and `os_breakdown` counted one more agent than
  `connection_summary` in the same reply. The manager is now left out of
  every count. Disconnected agents also reported `last_keepalive: null`,
  because the code read `last_keepalive` and the API field is
  `lastKeepAlive`.
- **Safety-layer tests (R6).** `tests/test_safety_layer.py` runs the real
  tools through `FastMCP.call_tool` with only `WazuhClient` mocked:
  confirmation gate, RBAC, rate limiting, validators, sanitizer and the SSE
  entry point. The four defects above were first committed as strict
  xfails, then fixed. The suite grows from 26 to 102 passing tests, with
  no xfails left.
- **Model-behaviour eval (R7).** `evals/` holds 15 cases (9 routing, 3
  output-mode, 3 destructive-flow) and a harness that loads the real server
  prompt and tool schemas. It runs against Anthropic or DeepSeek, needs
  `EVAL_MODEL` plus that provider's API key, and
  has no default model. Two runs on 2026-10-06 on deepseek-flash, both
  recorded as written in `evals/results/`:
  - 8/15 (routing 5/9, mode 3/3, destructive 0/3). The scorer read only
    the first of the model's parallel tool calls, so the destructive cases
    never reached the confirmation step.
  - 11/15 (routing 7/9, mode 2/3, destructive 2/3), after the first turn
    was scored as a set. Both cases that reached confirmation stopped for
    the user.

  Install with
  `pip install -e ".[eval]"`.
- **CI on Python 3.14 (R5),** the version the Docker image ships.
- **README "Known Limits" section (R8).**

### Known issues

- Inside the Docker demo, the loopback bind is not reachable through the
  published port 8000. Not covered by a test.
- Indexer hit counts stop at 10,000 (OpenSearch's default
  `track_total_hits`), so `total` and "Found N alert(s)" are a lower bound
  above that. Not covered by a test.

## [0.2.0] — 2026-06-11

### Hardening release: 28 tools, tested against Wazuh 4.14.5

Verified against Wazuh 4.14.5 on Ubuntu 22.04 with real agents, 7,514 alerts, 12 CVEs, 5,038 FIM records.

### Security & Production Hardening 🛡️
- **Audit logging**: Immutable, append-only JSONL audit trail for all destructive actions
- **Output sanitization**: Automatic redaction of credentials, API keys, JWT tokens, passwords from LLM-bound data
- **API rate limiting**: Per-tool token-bucket rate limiter with stricter limits on destructive tools (5/120s)
- **Input validation**: Shell metacharacter blocking, regex validation for agent IDs, IPs, CVEs, MITRE IDs, rule IDs
- **Dependency scanning**: GitHub Actions with pip-audit + CodeQL + Dependabot (weekly)
- **Non-root Docker**: Production container runs as unprivileged `wazuhmcp` user
- **RBAC**: 4 built-in roles (viewer, analyst, admin, soc) with hierarchical access and custom policy support
- **Prometheus metrics**: 7 metrics on `:9090/metrics` — tool calls, latency, rate limits, API health, audit entries
- **OpenAPI 3.0 / Swagger**: 24-path spec at `/openapi.json`, interactive UI at `/docs`

### Wazuh 4.14.5 Compatibility (Critical) 🤖
- **IndexerClient**: Queries OpenSearch directly for alerts, vulnerabilities, and rules (removed from REST API in 4.x/5.x)
- **Basic Auth fix**: Wazuh API authenticate endpoint requires HTTP Basic Auth, not JSON body
- **API path fixes**: `/mitre/techniques`, `/groups` (not `/agents/groups`), `/manager/daemons/stats`, `/lists/files`
- **Events endpoint**: Changed from GET to POST with `{"events": [...]}` body format
- **Agent lookup**: Uses `?agents_list=X` query param (no `/agents/{id}` endpoint in 4.x)
- **Rules fallback**: Extracts rule data from indexer when `/rules` returns 500 (known Wazuh 4.14.x bug)
- **Cluster fallback**: Falls back to manager daemon stats for single-node deployments
- **Indexer network**: Documented `network.bind_host: 0.0.0.0` fix to expose port 9200

### New Tools (12 added, 28 total) 📊
- **Agent groups**: `wazuh_list_groups`, `wazuh_get_group`, `wazuh_group_agents`
- **CDB lists**: `wazuh_list_cdb_lists`, `wazuh_get_cdb_list`
- **Manager logs**: `wazuh_manager_logs` with category and search filters
- **Cluster per-node**: `wazuh_cluster_node_stats` with single-node fallback
- **Rules coverage map**: `wazuh_rules_coverage_map` — MITRE, NIST 800-53, PCI DSS, GDPR, HIPAA
- **Vulnerability heatmap**: `wazuh_vulnerability_heatmap` — risk-scored per-agent CVE inventory
- **Incident timeline**: `wazuh_incident_timeline` — auto-generated event chronology
- **Token-efficient output**: `triage`, `detail`, `compliance`, `hunting`, `fleet` modes (60-80% token savings)

### Developer Experience 🧠
- **Comprehensive docs**: SECURITY.md (6-layer defense), DEVELOPMENT.md (architecture), ADVANCED_FEATURES.md, TROUBLESHOOTING.md (300+ lines, 15+ solved issues)
- **GitHub CI/CD**: Multi-Python test matrix (3.10-3.13), ruff linting, automated PyPI releases
- **Docker production**: Multi-stage build, health checks, non-root user
- **Multi-manager support**: Round-robin client pool via `WAZUH_API_URLS`
- **SSE transport**: `main_sse()` for web-based AI clients on port 8000

### Documentation 📚
- **TROUBLESHOOTING.md**: 15+ common Wazuh issues with root causes and fixes, network architecture diagram, debug mode, audit log inspection, Prometheus metrics reference
- **README.md**: Architecture diagram, data source column on every tool, complete env var reference, config examples
- **All `.env` and MCP config examples** updated with indexer credentials

## [0.1.0] — 2026-06-10

### Initial Release
- 16 MCP tools across 6 domains (alerts, hunting, compliance, agents, manager, response)
- Async Wazuh REST API client with JWT auth and auto-refresh
- Two-step confirmation gate for destructive tools (active response, agent commands)
- Docker Compose dev stack with Wazuh 4.9 single-node
- 12 pytest-asyncio tests
- Claude Desktop / Cursor MCP configuration
