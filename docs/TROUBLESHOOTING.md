# Troubleshooting Guide

Issues we hit, and how we fixed them, while getting Wazuh MCP Server working against Wazuh 4.14.5.

---

## Quick Diagnosis

```bash
# Run the built-in 28-tool diagnostic
python -c "
import asyncio, os
os.environ['WAZUH_INDEXER_PASS'] = 'your-indexer-password'
from wazuh_mcp.client import WazuhClient

async def test():
    c = WazuhClient(base_url='https://your-wazuh:55000', username='wazuh-wui', password='your-pass', insecure=True)
    for name in ['list_agents', 'list_alerts', 'sca_summary', 'syscheck', 'vulnerabilities', 'list_rules', 'manager_stats']:
        try:
            r = await getattr(c, name)(*(['000'] if name in ['sca_summary','syscheck'] else []), limit=3)
            total = r.get('total_affected_items', '?') if isinstance(r, dict) else '?'
            print(f'  ✅ {name}: {total} results')
        except Exception as e:
            print(f'  ❌ {name}: {e}')
    await c.close()
asyncio.run(test())
"
```

---

## Wazuh-Specific Issues

### ❌ Dashboard Version Mismatch

**Symptom:** Wazuh dashboard shows "API version: X.Y.Z. App version: A.B.C"

**Root cause:** The Wazuh dashboard plugin version doesn't match the Wazuh manager version. Common after partial upgrades.

**Fix:**
```bash
# Check actual manager version
sudo /var/ossec/bin/wazuh-control info | grep VERSION

# Upgrade dashboard to match
sudo apt install wazuh-dashboard=$(dpkg -l wazuh-manager | tail -1 | awk '{print $3}') -y
sudo systemctl restart wazuh-dashboard
```

### ❌ Dashboard Won't Start (Missing TLS Certs)

**Symptom:** `ENOENT: no such file or directory, open '/etc/wazuh-dashboard/certs/dashboard-key.pem'`

**Root cause:** After upgrading Wazuh dashboard, the TLS certificate files may be missing or in a different location.

**Fix (Option A — Disable SSL for dev):**
```bash
sudo sed -i 's/server\.ssl\.enabled:\s*true/server.ssl.enabled: false/' /etc/wazuh-dashboard/opensearch_dashboards.yml
sudo systemctl restart wazuh-dashboard
# Access at http://YOUR_HOST:443 (HTTP, not HTTPS)
```

**Fix (Option B — Generate new certs):**
```bash
sudo mkdir -p /etc/wazuh-dashboard/certs
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/wazuh-dashboard/certs/dashboard-key.pem \
  -out /etc/wazuh-dashboard/certs/dashboard.pem \
  -subj "/C=US/ST=State/L=City/O=Wazuh/CN=localhost"
sudo systemctl restart wazuh-dashboard
```

### ❌ `/alerts` Returns 404

**Symptom:** `GET /alerts → 404 Not Found`

**Root cause:** Wazuh 4.x/5.x **removed** the `/alerts` endpoint from the REST API. Alerts are stored in the Wazuh Indexer (OpenSearch) and must be queried directly on port 9200.

**Fix — Expose the indexer:**
```bash
# Wazuh Indexer only listens on localhost by default
echo 'network.bind_host: 0.0.0.0' | sudo tee -a /etc/wazuh-indexer/opensearch.yml
echo 'http.host: 0.0.0.0' | sudo tee -a /etc/wazuh-indexer/opensearch.yml
sudo systemctl restart wazuh-indexer

# Verify it's accessible
curl -k -u admin:YOUR_INDEXER_PASS https://YOUR_HOST:9200/
```

**Fix — Set MCP env vars:**
```bash
# In your .env or Zed MCP config:
WAZUH_INDEXER_URL=https://YOUR_HOST:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=YOUR_INDEXER_PASSWORD
```

> ⚠️ **Security note:** Only expose the indexer on trusted networks (VPN, internal subnet). Never expose port 9200 to the internet.

### ❌ `/rules` Returns 500 (Internal Error)

**Symptom:** `GET /rules → 500 Wazuh Internal Error` even with small limits.

**Root cause:** Known bug in Wazuh 4.14.x — the `/rules` endpoint crashes when it can't reach the indexer for rule metadata.

**Fix:** The MCP server automatically falls back to extracting rule data from the alerts index. No manual fix needed — this is handled by the indexer fallback in `src/wazuh_mcp/client.py`.

### ❌ `/vulnerability` Returns 404

**Symptom:** `GET /vulnerability/{agent_id} → 404`

**Root cause:** Like `/alerts`, the vulnerability endpoint was removed from the REST API. Vulnerability data lives in the `wazuh-states-vulnerabilities-*` index.

**Fix:** Same as the `/alerts` fix above — the MCP server's IndexerClient queries the indexer directly for vulnerabilities.

### ❌ Wazuh API Authentication Failing (401)

**Symptom:** `POST /security/user/authenticate` returns 401 with JSON body `{"user_id":"...","password":"..."}`

**Root cause:** Wazuh 4.x requires **HTTP Basic Auth** on the authenticate endpoint, not JSON body.

**Fix:** The MCP client uses Basic auth by default. If you're testing with curl:
```bash
# ✅ Correct (Basic Auth)
curl -k -u wazuh-wui:YOUR_PASS -X POST https://YOUR_HOST:55000/security/user/authenticate

# ❌ Wrong (JSON body)
curl -k -X POST https://YOUR_HOST:55000/security/user/authenticate \
  -d '{"user_id":"wazuh-wui","password":"YOUR_PASS"}'
```

### ❌ Indexer Returns 401 Unauthorized

**Symptom:** Indexer queries return 401 even though the Wazuh API works.

**Root cause:** The Wazuh Indexer (OpenSearch) uses **different credentials** than the Wazuh API. The indexer admin user is `admin`, with a password set during installation.

**Fix — Find your indexer password:**
```bash
# Check the internal users file
sudo grep -A2 "admin:" /etc/wazuh-indexer/opensearch-security/internal_users.yml

# Or reset it
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh --change-all
```

**Fix — Set in MCP config:**
```bash
export WAZUH_INDEXER_USER=admin
export WAZUH_INDEXER_PASS=YOUR_INDEXER_PASSWORD
```

### ❌ No Alerts in Dashboard

**Symptom:** Wazuh dashboard shows zero alerts.

**Root cause:** Fresh installs have no agents generating events. The manager itself (agent 000) generates some internal events but they may not be indexed.

**Fix — Generate test noise:**
```bash
# Simulate security events
for i in $(seq 1 8); do
  logger -p auth.warning "sshd[$((1000+i))]: Failed password for root from 10.0.0.$i port 22 ssh2"
done
logger -p auth.warning "sudo: test : user NOT in sudoers ; TTY=pts/0 ; COMMAND=/usr/bin/nmap"
logger -t apache "GET /../../etc/passwd HTTP/1.1"

# Wait 30 seconds for analysisd to process
sleep 30
```

### ❌ Filebeat / Indexer Connection Issues

**Symptom:** Filebeat logs show `ERROR Failed to connect to backoff(elasticsearch(...))`

**Root cause:** Filebeat can't reach the indexer, or the credentials are wrong.

**Fix:**
```bash
# Check filebeat status
sudo systemctl status filebeat
sudo journalctl -u filebeat --no-pager -n 20

# Verify indexer is listening
sudo ss -tlnp | grep 9200

# Test credentials
curl -k -u admin:YOUR_PASS https://localhost:9200/

# Update filebeat config
sudo nano /etc/filebeat/filebeat.yml
# Ensure:
#   output.elasticsearch:
#     hosts: ["https://127.0.0.1:9200"]
#     username: "admin"
#     password: "YOUR_PASS"

sudo systemctl restart filebeat
```

---

## MCP Server Issues

### ❌ MCP Server Won't Start (Import Error)

**Symptom:** `ModuleNotFoundError: No module named 'wazuh_mcp'`

**Fix:**
```bash
cd /path/to/sb-siem-mcp
pip install -e ".[dev]"
```

### ❌ MCP Server Can't Reach Wazuh API

**Symptom:** `WazuhAPIError: HTTPConnectionPool(host='...', port=55000)`

**Fix:**
1. Check Wazuh manager is running: `sudo systemctl status wazuh-manager`
2. Verify API port is exposed: `sudo ss -tlnp | grep 55000`
3. Check firewall: `sudo ufw status` — port 55000 must be allowed
4. Test from MCP machine: `curl -k https://Wazuh_IP:55000/`

### ❌ Rate Limiting Kicks In

**Symptom:** `Rate limit exceeded for wazuh_list_alerts`

**Fix:**
```bash
# Increase limits
export WAZUH_RATE_LIMIT_TOKENS=60
export WAZUH_RATE_LIMIT_PERIOD=30

# Or disable entirely
export WAZUH_RATE_LIMIT_TOKENS=9999
export WAZUH_RATE_LIMIT_PERIOD=1
```

### ❌ Claude Desktop / Zed Doesn't See Tools

**Symptom:** AI client connects but shows no Wazuh tools.

**Fix:**
1. Check MCP config path is correct in Claude Desktop / Zed settings
2. Ensure `cwd` points to the `src/` directory where `wazuh_mcp` is importable
3. Use absolute path to Python: `"command": "C:/Python314/python.exe"`
4. Check logs:
   - **Claude Desktop**: `~/Library/Logs/Claude/mcp*.log` (macOS) or `%APPDATA%\Claude\logs` (Windows)
   - **Zed**: Check the agent panel for MCP connection errors

### ❌ "Confirmation token expired"

**Symptom:** Active response tools return "Confirmation token has expired"

**Fix:** This is by design — tokens expire after 5 minutes for security. Simply call the tool again without `confirm=True` to get a fresh token. This prevents replay attacks.

---

## Network Architecture

### Production Setup

```
┌─────────────────────┐         ┌──────────────────────────┐
│  Analyst Workstation │         │  Wazuh VM / Server        │
│                     │         │                          │
│  Zed / Claude       │──HTTPS──▶│  Wazuh API :55000        │
│  + MCP Server       │         │                          │
│                     │──HTTPS──▶│  Wazuh Indexer :9200     │
└─────────────────────┘         └──────────────────────────┘
```

### Required Ports Open

| Port | Service | Protocol | Required? |
|------|---------|----------|-----------|
| 55000 | Wazuh REST API | HTTPS | ✅ Always |
| 9200 | Wazuh Indexer | HTTPS | ✅ For alerts/vulns/rules |
| 443 | Wazuh Dashboard | HTTP/HTTPS | Optional (web UI only) |

### Security Considerations

- Port 9200 should **never** be exposed to the internet
- Use a VPN or internal network between the MCP server and Wazuh
- For cloud deployments, use VPC peering or private endpoints
- The MCP server runs locally — it talks to Wazuh over the network
- Credentials go through `.env` (gitignored) — never commit them

---

## Debug Mode

```bash
# Enable verbose MCP logging
export WAZUH_MCP_LOG_LEVEL=DEBUG
python -m wazuh_mcp.server 2> debug.log

# In another terminal, watch:
tail -f debug.log
```

## Audit Log

```bash
# View recent destructive actions
tail -20 ~/.wazuh-mcp/audit.jsonl | python -m json.tool

# Count by tool
cat ~/.wazuh-mcp/audit.jsonl | python -c "
import sys, json
from collections import Counter
c = Counter()
for line in sys.stdin:
    try: c[json.loads(line)['tool']] += 1
    except: pass
for tool, count in c.most_common():
    print(f'{count:4d}  {tool}')
"
```

## Prometheus Metrics

The endpoint exists in SSE mode, but no tool records to these metrics yet,
so every value is zero (see Known Limits in the README).

```bash
# Check metrics endpoint
curl http://localhost:9090/metrics | grep wazuh_mcp

# Key metrics:
#   wazuh_mcp_tool_calls_total       — total API calls
#   wazuh_mcp_tool_duration_seconds  — latency histogram
#   wazuh_mcp_rate_limits_total      — rate limit hits
#   wazuh_mcp_api_up                 — 1=API reachable, 0=down
#   wazuh_mcp_audit_entries_total    — destructive actions logged
```

## Getting Help

1. **Check Wazuh logs on the VM:**
   ```bash
   sudo journalctl -u wazuh-manager --no-pager -n 50
   sudo journalctl -u wazuh-indexer --no-pager -n 50
   sudo tail -50 /var/ossec/logs/api.log
   ```

2. **Check MCP server logs** — look for `[ERROR]` lines in stderr output

3. **Verify indexer data:**
   ```bash
   curl -k -u admin:PASS https://YOUR_HOST:9200/_cat/indices/wazuh-*?v
   ```

4. **Open a GitHub Issue** with:
   - Wazuh version (`/var/ossec/bin/wazuh-control info`)
   - MCP server version (`python -c "import wazuh_mcp; print(wazuh_mcp.__version__)"`)
   - The exact error message
   - Output from the diagnostic script at the top of this page
