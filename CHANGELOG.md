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
  `main_sse()` defaults to it. See Known issues: SSE mode does not start in
  this release, and inside the container this bind is not reachable through
  the published port. (`b7e3596`)
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

- `mcp>=1.0.0,<2.0.0` (mcp 2.0 renamed `FastMCP` and broke the server
  import), `pydantic>=2.7.0,<3.0.0`, `pydantic-core>=2.18.0,<3.0.0`. Issue
  #5, PR #6. (`8e2e4ee`)

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
- **Safety-layer tests (R6).** `tests/test_safety_layer.py` runs the real
  tools through `FastMCP.call_tool` with only `WazuhClient` mocked:
  confirmation gate, RBAC, rate limiting, validators and sanitizer. The
  suite grows from 26 to 82 passing tests, plus 10 strict xfails that
  document the known issues below.
- **Model-behaviour eval (R7).** `evals/` holds 15 cases (9 routing, 3
  output-mode, 3 destructive-flow) and a harness that loads the real server
  prompt and tool schemas. It needs `EVAL_MODEL` and `ANTHROPIC_API_KEY` and
  has no default model. No run has been recorded yet. Install with
  `pip install -e ".[eval]"`.
- **CI on Python 3.14 (R5),** the version the Docker image ships.
- **README "Known Limits" section (R8).**

### Known issues

Each has a strict xfail test in `tests/test_safety_layer.py` unless noted.

- Built-in RBAC roles are not cumulative: each role holds only its own
  tier's tools.
- `wazuh_run_active_response` rejects every `arguments` value sent through
  MCP: FastMCP decodes the JSON array string into a list, then fails string
  validation.
- The ID validators accept a trailing newline (`"001\n"`).
- SSE mode raises `TypeError` on start: `FastMCP.run()` does not accept
  `host` or `port`.
- Inside the Docker demo, the loopback bind is not reachable through the
  published port 8000. Not covered by a test.

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
