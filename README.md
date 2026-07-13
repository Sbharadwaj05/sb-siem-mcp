# 🔐 SB SIEM MCP

> **Note:** Independent, third-party project — not affiliated with or endorsed
> by Wazuh Inc. Actively developed and tested against live Wazuh instances;
> review and test before production deployment.

**28 MCP tools. 9 domains. Tested on Wazuh 4.14.5 against live instances. AI-powered security operations for Wazuh SIEM/XDR.**

<p align="center">
  <a href="https://github.com/Sbharadwaj05/sb-siem-mcp/actions/workflows/ci.yml"><img src="https://github.com/Sbharadwaj05/sb-siem-mcp/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Sbharadwaj05/sb-siem-mcp/actions/workflows/security-scan.yml"><img src="https://github.com/Sbharadwaj05/sb-siem-mcp/actions/workflows/security-scan.yml/badge.svg" alt="Security Scan"></a>
  <img src="https://img.shields.io/badge/tools-28%20%2F%2028%20operational-brightgreen" alt="28/28 tools">
  <img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue" alt="Python">
  <a href="https://github.com/Sbharadwaj05/sb-siem-mcp/blob/master/LICENSE"><img src="https://img.shields.io/github/license/Sbharadwaj05/sb-siem-mcp" alt="License: MIT"></a>
</p>

> *"Show me all critical alerts in the last 6 hours, cross-reference with MITRE ATT&CK, and check if any affected hosts have unpatched CVEs."*

One prompt. Your AI assistant queries 7,514 alerts, checks 5,038 FIM records, scans 12 CVEs, cross-references 750 MITRE techniques, audits CIS compliance, and triggers incident response — all through your Wazuh infrastructure.

---

## How It Works (30 seconds)

You already have Wazuh running somewhere. The MCP server is a **local process** that your AI client spawns as a child — just like a language server or linter.

```
Your Machine                              Your Wazuh Server
┌────────────────────┐                   ┌──────────────────┐
│ Zed / Claude       │                   │                  │
│   │                │                   │  Wazuh API       │
│   ▼                │                   │  :55000          │
│ python -m          │───────HTTPS──────▶│                  │
│ wazuh_mcp.server   │                   │  Wazuh Indexer   │
│ (child process)    │───────HTTPS──────▶│  :9200           │
└────────────────────┘                   └──────────────────┘
```

**No Docker required. No containers. No agents to install.** Just point it at your existing Wazuh and start asking questions in natural language.

---

## 🛡️ Security Features (Defense in Depth)

- [x] **Input validation** — Shell metacharacter blocking, regex for agent IDs, IPs, CVEs, MITRE IDs
- [x] **Rate limiting** — Token-bucket: 30/60s for read tools, 5/120s for destructive
- [x] **Output sanitization** — Redacts AWS keys, JWT tokens, SSH keys, API keys, passwords from LLM-bound data
- [x] **Audit logging** — Append-only JSONL trail for all destructive actions
- [x] **Confirmation gate** — Two-step `confirm=True` + expiring token for active response tools
- [x] **RBAC** — 4 built-in roles: `viewer`, `analyst`, `admin`, `soc` with hierarchical access
- [x] **Dependabot + pip-audit + CodeQL** — Automated dependency scanning on every push + weekly schedule
- [x] **Non-root Docker** — Production container runs as unprivileged `wazuhmcp` user
- [x] **TLS support** — Verify server certificates, or disable for local dev via `WAZUH_INSECURE`
- [x] **Prometheus metrics** — 7 metrics exposed on `:9090/metrics` for SOC monitoring (latency, errors, rate limits)
- [x] **OpenAPI 3.0 / Swagger UI** — Interactive API docs at `/docs`, raw spec at `/openapi.json`

---

## 📊 Architecture

```
┌──────────────────────────┐         ┌──────────────────────────┐
│  Your AI Client           │         │  Wazuh Infrastructure     │
│  (Zed / Claude / Cursor)  │         │                          │
│          │                │         │  Wazuh API :55000        │
│          ▼                │         │  ├─ Agents, Groups       │
│  ┌──────────────────┐     │         │  ├─ SCA, FIM, MITRE     │
│  │  MCP Server       │────HTTPS────▶│  ├─ Manager, Cluster    │
│  │  28 tools         │     │         │  └─ Active Response     │
│  │                  │     │         │                          │
│  │  WazuhClient ────┼────HTTPS────▶│  Wazuh Indexer :9200    │
│  │  IndexerClient ───┤     │         │  ├─ Alerts (7,514+)     │
│  │  RateLimiter     │     │         │  ├─ Vulnerabilities      │
│  │  Sanitizer       │     │         │  └─ Events, Rules       │
│  │  RBACEnforcer    │     │         │                          │
│  └──────────────────┘     │         └──────────────────────────┘
│          │                │
│    :9090/metrics           │
│    :8000/docs              │
└──────────────────────────┘
```

The MCP server talks to **both** the Wazuh REST API (port 55000, for management) and the Wazuh Indexer (port 9200, for alerts/vulnerabilities). In Wazuh 4.x/5.x, alerts and vulnerabilities are indexer-only — not available via the REST API. The server's `IndexerClient` handles this transparently.

---

## 📊 What This Does

| Workflow | Example Prompt | Tools Used |
|----------|---------------|------------|
| **Alert Triage** | *"Summarize today's alerts by severity and MITRE technique"* | `list_alerts`, `alert_summary`, `get_alert` |
| **Threat Hunting** | *"Search for IOC 10.0.0.50 across all events and FIM records"* | `search_events`, `query_fim`, `search_mitre` |
| **Compliance Audit** | *"Show me all agents failing CIS benchmark checks"* | `sca_status`, `sca_checks`, `compliance_report` |
| **Rules Coverage** | *"What's my NIST 800-53 detection coverage?"* | `rules_coverage_map`, `rules_info` |
| **Vulnerability Mgmt** | *"Which systems have critical unpatched CVEs?"* | `query_vulnerabilities`, `vulnerability_heatmap` |
| **Incident Timeline** | *"Reconstruct what happened around alert #45821"* | `incident_timeline`, `search_events`, `query_fim` |
| **Fleet Management** | *"List disconnected agents and their groups"* | `list_agents`, `get_agent`, `agent_health`, `list_groups` |
| **Threat Intel** | *"Show me the CDB blocklists and MITRE techniques for T1059"* | `list_cdb_lists`, `get_cdb_list`, `search_mitre` |
| **Incident Response** ⚠️ | *"Block IP 203.0.113.55 on all web servers"* | `run_active_response` (with confirmation) |

---

## 📦 Installation

### pip (from PyPI — coming soon)

```bash
pip install sb-siem-mcp
```

### From source

```bash
git clone https://github.com/Sbharadwaj05/sb-siem-mcp.git
cd sb-siem-mcp
pip install -e ".[dev]"
```

### Docker (one‑command demo — spins up Wazuh + MCP for testing)

> ⚠️ **This bundles a full Wazuh stack for quick demos. In production, you already have Wazuh running — just use the pip install above and point to your existing Wazuh.**
>
> 🔒 **The MCP endpoint has no built-in client authentication.** The demo server binds to `localhost:8000` — keep it local. For remote access, place it behind a reverse proxy with auth. See [Production Hardening](#-production-hardening) below.

```bash
git clone https://github.com/Sbharadwaj05/sb-siem-mcp.git
cd sb-siem-mcp
docker compose up -d

# Wazuh Dashboard:   https://localhost:443
# Swagger UI:         http://localhost:8000/docs
# Prometheus Metrics: http://localhost:9090/metrics
```

### Configuration

Create a `.env` file:

```bash
# Required
WAZUH_API_URL=https://your-wazuh-manager:55000
WAZUH_USERNAME=wazuh-wui
WAZUH_PASSWORD=your-api-password

# Required for alerts, vulnerabilities, rules (Wazuh 4.x/5.x)
WAZUH_INDEXER_URL=https://your-wazuh-manager:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=your-indexer-password

# Optional
WAZUH_INSECURE=true                    # Skip TLS verification (dev only)
WAZUH_RBAC_ROLE=analyst                # Restrict tools by role
WAZUH_RATE_LIMIT_TOKENS=30             # Rate limit burst
WAZUH_RATE_LIMIT_PERIOD=60             # Rate limit window
```

> **Important:** The Wazuh Indexer (port 9200) must be accessible from the MCP server. By default it only listens on `localhost`. See [Troubleshooting](docs/TROUBLESHOOTING.md) for the one-line fix.

### Claude Desktop / Zed / Cursor

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python",
      "args": ["-m", "wazuh_mcp.server"],
      "cwd": "/path/to/sb-siem-mcp/src",
      "env": {
        "WAZUH_API_URL": "https://192.168.56.102:55000",
        "WAZUH_USERNAME": "wazuh-wui",
        "WAZUH_PASSWORD": "your-api-password",
        "WAZUH_INSECURE": "true",
        "WAZUH_INDEXER_PASS": "your-indexer-password"
      }
    }
  }
}
```

---

## 🔧 Complete Tool Reference (28 tools, 9 domains)

### 🔔 Alerts & Triage (3)
| Tool | Description | Data Source |
|------|-------------|-------------|
| `wazuh_list_alerts` | Query alerts by severity, agent, rule ID, MITRE, search | Wazuh Indexer |
| `wazuh_get_alert` | Fetch single alert by ID with full context | Wazuh Indexer |
| `wazuh_alert_summary` | Aggregated: severity distribution, top rules/IPs, MITRE coverage | Wazuh Indexer |

### 🔍 Threat Hunting (4)
| Tool | Description | Data Source |
|------|-------------|-------------|
| `wazuh_search_events` | Submit raw events for Wazuh parsing/analysis | Wazuh API |
| `wazuh_query_fim` | File Integrity Monitoring — file changes, additions, deletions | Wazuh API |
| `wazuh_query_vulnerabilities` | CVE inventory per agent, filterable by severity | Wazuh Indexer |
| `wazuh_search_mitre` | MITRE ATT&CK techniques, tactics, mitigations, groups | Wazuh API |

### 📋 Compliance (3)
| Tool | Description | Data Source |
|------|-------------|-------------|
| `wazuh_sca_status` | SCA policy scores per agent (CIS, PCI DSS, NIST, GDPR) | Wazuh API |
| `wazuh_sca_checks` | Per-check pass/fail detail with rationales and remediation | Wazuh API |
| `wazuh_compliance_report` | Fleet-wide compliance aggregation across all agents | Wazuh API |

### 🖥️ Agents & Groups (6)
| Tool | Description | Data Source |
|------|-------------|-------------|
| `wazuh_list_agents` | List agents with status, OS, version, search, pagination | Wazuh API |
| `wazuh_get_agent` | Deep-dive on single agent: config, modules, groups | Wazuh API |
| `wazuh_agent_health` | Fleet health: status counts, OS breakdown, stale agents | Wazuh API |
| `wazuh_list_groups` | List agent groups with counts and checksums | Wazuh API |
| `wazuh_get_group` | Group details, configuration, member counts | Wazuh API |
| `wazuh_group_agents` | All agents in a specific group | Wazuh API |

### 📚 CDB Lists (2)
| Tool | Description | Data Source |
|------|-------------|-------------|
| `wazuh_list_cdb_lists` | List CDB threat-intel files (IP blocklists, IOC databases) | Wazuh API |
| `wazuh_get_cdb_list` | Read contents of a CDB list file | Wazuh API |

### ⚙️ Manager & Cluster (5)
| Tool | Description | Data Source |
|------|-------------|-------------|
| `wazuh_manager_stats` | Daemon statistics (EPS, queues, processed events) | Wazuh API |
| `wazuh_manager_logs` | Manager log retrieval with category and search filters | Wazuh API |
| `wazuh_cluster_status` | Cluster health: enabled/running state | Wazuh API |
| `wazuh_cluster_node_stats` | Per-node daemon stats (falls back to manager stats for single-node) | Wazuh API |
| `wazuh_rules_info` | Search rules by framework/MITRE (falls back to indexer on 4.14.x bug) | Wazuh API / Indexer |

### 📊 Security Analysis (3)
| Tool | Description | Data Source |
|------|-------------|-------------|
| `wazuh_rules_coverage_map` | MITRE/NIST/PCI/GDPR/HIPAA coverage matrix vs your rules | Wazuh Indexer |
| `wazuh_vulnerability_heatmap` | Risk-scored CVE heatmap across all agents | Wazuh Indexer |
| `wazuh_incident_timeline` | Auto-generated chronological attack timeline from an alert | Wazuh Indexer |

### ⚠️ Incident Response (2)
| Tool | Description | Data Source |
|------|-------------|-------------|
| `wazuh_run_active_response` | Trigger firewall-drop, host-deny, restart-wazuh (with confirmation gate) | Wazuh API |
| `wazuh_agent_command` | Execute command on remote agent (with confirmation gate) | Wazuh API |

> **🔒 SAFETY**: Destructive tools require two-step `confirm=True` + one-time expiring token. A misconfigured LLM cannot silently block IPs or quarantine hosts. All destructive actions are recorded in an append-only audit log.

---

## 🖥️ Observability

### Prometheus Metrics (`:9090/metrics`)

| Metric | Type | Description |
|--------|------|-------------|
| `wazuh_mcp_tool_calls_total` | Counter | Tool invocations by name + status (success/error) |
| `wazuh_mcp_tool_duration_seconds` | Histogram | P50/P95/P99 latency per tool |
| `wazuh_mcp_rate_limits_total` | Counter | Rate-limit rejections per tool |
| `wazuh_mcp_api_up` | Gauge | Wazuh API connectivity (1=up, 0=down) |
| `wazuh_mcp_audit_entries_total` | Counter | Destructive actions logged |
| `wazuh_mcp_active_requests` | Gauge | In-flight tool calls |
| `wazuh_mcp_tool_errors_total` | Counter | Errors by tool + error type |

### OpenAPI / Swagger (`:8000/docs`)

Interactive API docs for all 28 tools. Raw OpenAPI 3.0 spec at `/openapi.json`.

### Audit Log (`~/.wazuh-mcp/audit.jsonl`)

Append-only JSON Lines. One entry per destructive action. Never truncated. Thread-safe.

---

## 🔐 RBAC

Four built-in roles with hierarchical, cumulative access:

| Role | Access | Tools |
|------|--------|-------|
| `viewer` | Read-only | Alerts, agents, compliance, rules |
| `analyst` | + Investigation | All viewer + hunting, MITRE, CDB lists, analysis |
| `admin` | + Administration | All analyst + manager stats, logs, cluster |
| `soc` | + Response ⚠️ | All admin + active response, agent commands |

```bash
export WAZUH_RBAC_ROLE=analyst
# Or custom policy: WAZUH_RBAC_POLICY=/path/to/rbac.json
```

---

## 📁 Project Structure

```
sb-siem-mcp/
├── src/wazuh_mcp/
│   ├── server.py           # FastMCP entry point (stdio + SSE transport)
│   ├── client.py           # Wazuh REST API client (JWT, Basic Auth, fallback)
│   ├── indexer.py          # Wazuh Indexer / OpenSearch client (alerts, vulns)
│   ├── rbac.py             # Role-Based Access Control (4 roles, custom policies)
│   ├── audit.py            # Immutable audit logging (JSONL, append-only)
│   ├── sanitizer.py        # Output sanitization (credential redaction)
│   ├── rate_limiter.py     # Token-bucket per-tool rate limiting
│   ├── validators.py       # Input validation (regex, shell metacharacter blocking)
│   ├── metrics.py          # Prometheus metrics exporter (7 metrics)
│   ├── openapi.py          # OpenAPI 3.0 spec + Swagger UI generator
│   ├── output.py           # Token-efficient field selection (5 modes)
│   ├── utils.py            # JSON formatters, pagination helpers
│   └── tools/              # 9 tool modules, 28 MCP tools
│       ├── alerts.py       # 3 tools: list, get, summary
│       ├── hunting.py      # 4 tools: events, fim, vulns, mitre
│       ├── compliance.py   # 3 tools: sca status, checks, report
│       ├── agents.py       # 3 tools: list, get, health
│       ├── groups.py       # 3 tools: list, get, group agents
│       ├── lists.py        # 2 tools: list cdb, get cdb
│       ├── manager.py      # 5 tools: stats, logs, cluster, node, rules
│       ├── analysis.py     # 3 tools: coverage, heatmap, timeline
│       └── response.py     # 2 tools: active response, agent command (safety-gated)
├── tests/                  # pytest-asyncio test suite (12 tests, all passing)
├── docs/                   # SECURITY, DEVELOPMENT, ADVANCED_FEATURES, TROUBLESHOOTING
├── scripts/setup.sh        # One-command Wazuh + MCP dev environment
├── docker-compose.yml      # Wazuh 4.9 + MCP server + Prometheus
├── Dockerfile              # Multi-stage production build (non-root)
├── openapi.json            # Generated OpenAPI 3.0 specification (24 paths)
├── .github/workflows/      # CI (test matrix), Release, Security Scan
├── CHANGELOG.md
└── README.md
```

---

## 🚀 Quick Start

```bash
# 1. Clone
git clone https://github.com/Sbharadwaj05/sb-siem-mcp.git
cd sb-siem-mcp

# 2. Configure
cp .env.example .env
# Edit .env with your Wazuh API + Indexer credentials

# 3. Install
pip install -e ".[dev]"

# 4. Verify connectivity
python -c "
from wazuh_mcp.client import WazuhClient
import asyncio
async def t():
    c = WazuhClient(insecure=True)
    print('Agents:', (await c.list_agents(limit=1)).get('total_affected_items','?'))
    print('Alerts:', (await c.list_alerts(limit=1)).get('total_affected_items','?'))
    await c.close()
asyncio.run(t())
"

# 5. Connect to AI client
# Copy claude_desktop_config.json.example into your MCP config
```

---

## 🔒 Production Hardening

This project ships with safe defaults, but the docker-compose demo stack disables
several security features for ease of local testing. **Do not use the demo config
in production** without these changes:

### 1. Enable TLS Everywhere

- Set `WAZUH_INSECURE=false` — the docker-compose now defaults to `false`.
- Re-enable the Wazuh Indexer security plugin — remove
  `DISABLE_SECURITY_PLUGIN=true` and `plugins.security.disabled=true` from the
  `wazuh.indexer` service. Generate proper certificates instead.
- Set `FILEBEAT_SSL_VERIFICATION_MODE=full` on the Wazuh Manager.

### 2. Restrict the MCP Endpoint

The MCP server exposes an HTTP endpoint on port 8000. **This endpoint has no
built-in client authentication.** In production:
- Bind to `127.0.0.1` if the AI client runs on the same host, OR
- Place the MCP server behind a reverse proxy with mutual TLS / API key auth, OR
- Use network-level controls (firewall rules, security groups) to restrict access.

### 3. Secure the Wazuh Indexer

The Indexer (port 9200) must be network-accessible from the MCP server.
- Use TLS with certificate verification (`WAZUH_INSECURE=false`).
- Store Indexer credentials in a secrets manager (Docker secrets, Kubernetes
  secrets, HashiCorp Vault) — never in plaintext `.env` files in production.
- Consider IP whitelisting at the network/firewall layer.

### 4. Harden the Audit Log

- The default audit log location is `~/.wazuh-mcp/audit.jsonl`. In production,
  set `WAZUH_AUDIT_LOG=/var/log/wazuh-mcp/audit.jsonl` (or another persistent
  volume outside the home directory).
- For true immutability, ship audit logs to an external SIEM or use a
  write-once-read-many (WORM) filesystem.

### 5. RBAC: Enable It

RBAC is disabled by default (`WAZUH_RBAC_ROLE` is unset → all tools available).
In production, set `WAZUH_RBAC_ROLE=analyst` (or stricter) and configure tool
permissions in your AI client to match.

### 6. Version Compatibility

This server targets Wazuh 4.x (tested on 4.14.5). Wazuh 5.x replaces the Indexer
with a new storage back-end — this server will require updates to work with 5.x.
Check your Wazuh version before deploying.

## 🔒 Security Policy

See [docs/SECURITY.md](docs/SECURITY.md) for full defense-in-depth documentation
(6 layers), production deployment checklist, and vulnerability reporting process.

## 🛠️ Troubleshooting

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for solutions to:
- Wazuh dashboard version mismatch
- `/alerts` returning 404 (indexer setup)
- `/rules` returning 500 (Wazuh 4.14.x bug + indexer fallback)
- Indexer 401 authentication
- Filebeat connection issues
- MCP server connectivity
- Rate limiting and confirmation gate behavior
- Complete network architecture diagram

## 📄 License

MIT © [Sbharadwaj05](https://github.com/Sbharadwaj05)

Need custom detection rules, SIEM tuning, or an MCP server built? Topmate: https://topmate.io/subhash_bharadwaj or DM for Fiverr gig links.
