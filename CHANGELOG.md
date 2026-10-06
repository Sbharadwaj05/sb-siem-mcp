# Changelog

All notable changes to the sb-siem-mcp project.

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
