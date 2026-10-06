"""
Async HTTP client for the Wazuh REST API (v4.7+).

Handles JWT authentication, automatic token refresh, pagination,
and translates Wazuh error codes into Python exceptions.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional

import httpx
from dotenv import load_dotenv

from wazuh_mcp.errors import WazuhAPIError
from wazuh_mcp.indexer import IndexerClient
from wazuh_mcp.validators import validate_ip

load_dotenv()

logger = logging.getLogger("wazuh-mcp.client")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------

DEFAULT_BASE_URL = os.getenv("WAZUH_API_URL", "https://localhost:55000")
DEFAULT_USERNAME = os.getenv("WAZUH_USERNAME", "admin")
DEFAULT_PASSWORD = os.getenv("WAZUH_PASSWORD", "")
DEFAULT_INSECURE = os.getenv("WAZUH_INSECURE", "false").lower() == "true"
DEFAULT_TIMEOUT = int(os.getenv("WAZUH_TIMEOUT", "30"))


class WazuhClient:
    """
    Async HTTP client for the Wazuh manager REST API.

    Authenticates once and transparently refreshes the JWT on expiry.
    All public methods return the ``data`` field from the Wazuh JSON envelope.

    Supports multi-manager failover: pass ``fallback_clients`` for automatic
    retry on connection/timeout errors.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        username: str = DEFAULT_USERNAME,
        password: str = DEFAULT_PASSWORD,
        insecure: bool = DEFAULT_INSECURE,
        timeout: int = DEFAULT_TIMEOUT,
        fallback_clients: Optional[List["WazuhClient"]] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self._fallback_clients = fallback_clients or []

        # TLS client certificate support (mTLS)
        _cert_path = os.getenv("WAZUH_CLIENT_CERT", "")
        _key_path = os.getenv("WAZUH_CLIENT_KEY", "")
        _cert: Optional[tuple] = None
        if _cert_path and _key_path:
            _cert = (_cert_path, _key_path)
            logger.info("TLS client certificate enabled: %s", _cert_path)

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout),
            verify=not insecure,
            cert=_cert,
        )
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0

        # Indexer client for alert/vulnerability queries
        idx_url = os.getenv(
            "WAZUH_INDEXER_URL", self.base_url.replace(":55000", ":9200")
        )
        idx_user = os.getenv("WAZUH_INDEXER_USER", "admin")
        idx_pass = os.getenv("WAZUH_INDEXER_PASS", "admin")
        self._indexer = IndexerClient(
            base_url=idx_url,
            username=idx_user,
            password=idx_pass,
            insecure=insecure,
        )

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    async def login(self) -> None:
        """Authenticate and cache a JWT token using HTTP Basic Auth."""
        import base64

        # Wazuh API accepts Basic auth on the /authenticate endpoint
        credentials = f"{self.username}:{self.password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        resp = await self._client.post(
            "/security/user/authenticate",
            headers={"Authorization": f"Basic {encoded}"},
        )
        data = self._unwrap(resp)
        token = data["token"]
        self._token = token
        self._token_expiry = time.time() + 840  # refresh 60s before 900s expiry
        logger.info("Wazuh API authentication successful")

        # Validate JWT token structure and claims
        self._validate_jwt(token)

    async def _ensure_auth(self) -> None:
        """Re-login if the token is missing or expired."""
        if self._token is None or time.time() >= self._token_expiry:
            await self.login()

    def _validate_jwt(self, token: str) -> None:
        """
        Validate JWT token structure and claims.

        Logs a warning (not error) if validation fails, since some Wazuh
        setups use opaque tokens rather than standard JWTs.
        """
        import base64
        import json as _json

        # Check JWT structure: header.payload.signature
        parts = token.split(".")
        if len(parts) != 3:
            logger.warning(
                "JWT validation: token has %d dot-separated parts (expected 3). "
                "This may be an opaque token — authentication will still work.",
                len(parts),
            )
            return

        # Decode payload (second segment)
        try:
            payload_b64 = parts[1]
            # Add padding if needed
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload = _json.loads(payload_bytes)
        except Exception as e:
            logger.warning("JWT validation: failed to decode payload — %s", e)
            return

        # Validate exp claim
        exp = payload.get("exp")
        if exp is not None:
            if time.time() > exp:
                logger.warning(
                    "JWT validation: token 'exp' claim (%s) is in the past. "
                    "The token may be rejected by the API.",
                    exp,
                )
        else:
            logger.warning(
                "JWT validation: token has no 'exp' claim. "
                "Cannot verify expiration from token payload."
            )

        # Validate iss claim
        iss = payload.get("iss")
        if iss is not None:
            if iss != self.base_url:
                logger.warning(
                    "JWT validation: 'iss' claim (%s) does not match API URL (%s).",
                    iss,
                    self.base_url,
                )
        else:
            logger.warning(
                "JWT validation: token has no 'iss' claim. "
                "Cannot verify issuer from token payload."
            )

    # ------------------------------------------------------------------
    # Low-level HTTP
    # ------------------------------------------------------------------

    async def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return await self._request("GET", path, params=params)

    async def _put(
        self,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return await self._request("PUT", path, params=params, json=json)

    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> Any:
        await self._ensure_auth()

        # Try primary client, then fallback clients on connection errors
        clients = [(self, self._token)] + [(fb, None) for fb in self._fallback_clients]
        last_error = None

        for client, token in clients:
            if token is None:
                # Fallback client — authenticate with its own base URL
                await client._ensure_auth()
                token = client._token

            headers = {"Authorization": f"Bearer {token}"}
            try:
                resp = await client._client.request(
                    method, path, params=params, json=json, headers=headers
                )
                return self._unwrap(resp)
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                last_error = exc
                if client is not self:
                    logger.warning("Retrying on fallback manager: %s", client.base_url)
                continue

        raise last_error  # type: ignore[misc]

    @staticmethod
    def _unwrap(resp: httpx.Response) -> Any:
        """Parse the Wazuh JSON envelope ``{"data": ..., "error": 0}``."""
        if resp.is_error:
            text = resp.text[:500]
            raise WazuhAPIError(resp.status_code, f"HTTP {resp.status_code}: {text}")

        try:
            body = resp.json()
        except Exception:
            raise WazuhAPIError(resp.status_code, "Invalid JSON response body")

        error_code = body.get("error", -1)
        if error_code != 0:
            msg = body.get("message", "Unknown API error")
            details = body.get("detail", "")
            # Per-item reasons ("The command used is not defined ...") are
            # only in data.failed_items; the top-level message is generic.
            data = body.get("data")
            failed = data.get("failed_items", []) if isinstance(data, dict) else []
            reasons = sorted(
                {
                    f["error"]["message"]
                    for f in failed
                    if isinstance(f, dict) and isinstance(f.get("error"), dict)
                    and "message" in f["error"]
                }
            )
            if reasons:
                details = "; ".join(filter(None, [details, *reasons]))
            raise WazuhAPIError(error_code, f"{msg} — {details}" if details else msg)

        return body.get("data", {})

    async def close(self) -> None:
        await self._client.aclose()

    # ==================================================================
    # Public API methods — organized by domain
    # ==================================================================

    # ---- Alerts -------------------------------------------------------

    async def list_alerts(
        self,
        *,
        agent_id: Optional[str] = None,
        agents_list: Optional[str] = None,
        min_level: Optional[int] = None,
        rule_id: Optional[str] = None,
        rule_ids: Optional[str] = None,
        mitre_id: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        sort: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Query alerts — tries REST API first, falls back to indexer."""
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if agent_id:
            params["agent_id"] = agent_id
        if agents_list:
            params["agents_list"] = agents_list
        if search:
            params["search"] = search
        if select:
            params["select"] = select
        if sort:
            params["sort"] = sort
        filters = []
        if min_level is not None:
            filters.append(f"rule.level>={min_level}")
        if rule_id:
            filters.append(f"rule.id={rule_id}")
        if rule_ids:
            filters.append(f"rule.id({rule_ids})")
        if mitre_id:
            filters.append(f"rule.mitre.id={mitre_id}")
        if filters:
            params["q"] = ";".join(filters)
        try:
            return await self._get("/alerts", params=params)
        except WazuhAPIError:
            return await self._indexer.list_alerts(
                min_level=min_level,
                agent_id=agent_id,
                rule_id=rule_id,
                search=search,
                mitre_id=mitre_id,
                limit=limit,
                offset=offset,
            )

    async def get_alert(self, alert_id: str) -> Dict[str, Any]:
        """Fetch a single alert — tries API, falls back to indexer."""
        try:
            data = await self._get(
                "/alerts", params={"q": f"id={alert_id}", "limit": 1}
            )
            items = data.get("affected_items", []) if isinstance(data, dict) else data
            if not items:
                raise WazuhAPIError(404, f"Alert {alert_id} not found")
            return items[0]
        except WazuhAPIError:
            return await self._indexer.get_alert(alert_id)

    # ---- Events (raw) -------------------------------------------------

    async def search_events(
        self,
        *,
        search: Optional[str] = None,
        select: Optional[str] = None,
        sort: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        filters: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Submit raw event strings for parsing by Wazuh analysis engine."""
        body: Dict[str, Any] = {
            "events": [search] if search else [],
        }
        return await self._request("POST", "/events", json=body)

    # ---- Agents -------------------------------------------------------

    async def list_agents(
        self,
        *,
        status: Optional[str] = None,
        older_than: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[str] = None,
        sort: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List registered agents with optional filters."""
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
        if older_than:
            params["older_than"] = older_than
        if search:
            params["search"] = search
        if select:
            params["select"] = select
        if sort:
            params["sort"] = sort
        return await self._get("/agents", params=params)

    async def get_agent(self, agent_id: str) -> Dict[str, Any]:
        """Get full details for a single agent (via query filter)."""
        data = await self._get("/agents", params={"agents_list": agent_id, "limit": 1})
        items = data.get("affected_items", []) if isinstance(data, dict) else data
        if not items:
            raise WazuhAPIError(404, f"Agent {agent_id} not found")
        return items[0]

    async def agent_summary(self) -> Dict[str, Any]:
        """Get an overview of agent connection statuses."""
        return await self._get("/agents/summary/status")

    # ---- SCA (Security Configuration Assessment) ----------------------

    async def sca_checks(
        self,
        agent_id: str,
        *,
        policy_id: Optional[str] = None,
        search: Optional[str] = None,
        result: Optional[str] = None,  # "passed" | "failed"
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Get SCA check results for an agent/policy."""
        if policy_id:
            path = f"/sca/{agent_id}/checks/{policy_id}"
        else:
            path = f"/sca/{agent_id}/checks"
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if search:
            params["search"] = search
        if result:
            params["result"] = result
        return await self._get(path, params=params)

    async def sca_summary(self, agent_id: str = "000") -> Dict[str, Any]:
        """Get SCA compliance summary for an agent."""
        return await self._get(f"/sca/{agent_id}")

    # ---- Syscheck / FIM -----------------------------------------------

    async def syscheck(
        self,
        agent_id: str,
        *,
        file_path: Optional[str] = None,
        event_type: Optional[str] = None,  # "added" | "modified" | "deleted"
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Query file-integrity monitoring records."""
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if file_path:
            params["file"] = file_path
        if event_type:
            params["type"] = event_type
        if search:
            params["search"] = search
        return await self._get(f"/syscheck/{agent_id}", params=params)

    # ---- Vulnerabilities ----------------------------------------------

    async def vulnerabilities(
        self,
        agent_id: str,
        *,
        cve: Optional[str] = None,
        severity: Optional[str] = None,  # Critical | High | Medium | Low
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Query vulnerabilities — tries API first, falls back to indexer."""
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if cve:
            params["cve"] = cve
        if severity:
            params["severity"] = severity
        if search:
            params["search"] = search
        try:
            return await self._get(f"/vulnerability/{agent_id}", params=params)
        except WazuhAPIError:
            return await self._indexer.vulnerabilities(
                severity=severity,
                cve=cve,
                limit=limit,
                offset=offset,
            )

    # ---- MITRE ATT&CK -------------------------------------------------

    async def mitre(
        self,
        *,
        search: Optional[str] = None,
        technique_id: Optional[str] = None,
        select: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Query MITRE ATT&CK framework information from Wazuh."""
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if search:
            params["search"] = search
        if technique_id:
            params["technique_id"] = technique_id
        if select:
            params["select"] = select
        return await self._get("/mitre/techniques", params=params)

    # ---- Manager / Cluster --------------------------------------------

    async def manager_stats(self, daemon: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve Wazuh manager daemon statistics (uses /manager/daemons/stats)."""
        params = {}
        if daemon:
            params["daemons_list"] = daemon
        return await self._get("/manager/daemons/stats", params=params)

    async def manager_status(self) -> Dict[str, Any]:
        """Get Wazuh manager health status."""
        return await self._get("/manager/status")

    async def manager_info(self) -> Dict[str, Any]:
        """Get Wazuh manager version and installation info."""
        return await self._get("/manager/info")

    async def cluster_nodes(self) -> Dict[str, Any]:
        """List cluster nodes and their status."""
        return await self._get("/cluster/nodes")

    async def cluster_status(self) -> Dict[str, Any]:
        """Get overall cluster health status."""
        return await self._get("/cluster/status")

    # ---- Rules --------------------------------------------------------

    async def list_rules(
        self,
        *,
        search: Optional[str] = None,
        level: Optional[int] = None,
        pci: Optional[str] = None,
        gdpr: Optional[str] = None,
        hipaa: Optional[str] = None,
        nist_800_53: Optional[str] = None,
        mitre: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        List/search Wazuh rules. Tries REST API first, falls back to
        extracting rule data from the alerts index (Wazuh 4.x/5.x bug).
        """
        # Try /rules/files first (works), then extract rules from indexer alerts
        try:
            params: Dict[str, Any] = {"limit": limit, "offset": offset}
            if search:
                params["search"] = search
            if level is not None:
                params["level"] = str(level)
            if pci:
                params["pci_dss"] = pci
            if gdpr:
                params["gdpr"] = gdpr
            if hipaa:
                params["hipaa"] = hipaa
            if nist_800_53:
                params["nist_800_53"] = nist_800_53
            if mitre:
                params["mitre"] = mitre
            return await self._get("/rules", params=params)
        except WazuhAPIError:
            # Wazuh 4.14.5 /rules endpoint returns 500 — extract from indexer
            query_parts = []
            if search:
                query_parts.append(search)
            if mitre:
                query_parts.append(mitre)
            qs = " ".join(query_parts) if query_parts else "*"
            return await self._indexer.search_events(
                search=qs, index="wazuh-alerts-*", limit=min(limit, 200), offset=offset
            )

    # ---- Active Response ----------------------------------------------

    async def run_active_response(
        self,
        agent_id: str,
        command: str,
        *,
        arguments: Optional[List[str]] = None,
        custom: bool = False,
    ) -> Dict[str, Any]:
        """
        Trigger an active-response command on an agent.

        .. danger::
           This is a destructive API. Always validate the command and
           target before calling.
        """
        # Wazuh 4.x: agents are targeted with the agents_list query parameter,
        # and the body accepts only command, arguments and alert. A command
        # starting with "!" runs that active-response script on the agent by
        # name; without it, the command must be enabled in the manager's
        # <active-response> configuration.
        body: Dict[str, Any] = {"command": f"!{command}" if custom else command}
        if arguments:
            body["arguments"] = arguments
            # Active-response scripts read the target IP from alert.data.srcip,
            # not from arguments, so lift the documented ["srcip", "<ip>", ...]
            # form into the alert the script will see.
            if "srcip" in arguments[:-1]:
                srcip = arguments[arguments.index("srcip") + 1]
                body["alert"] = {"data": {"srcip": validate_ip(srcip, "srcip")}}

        return await self._put(
            "/active-response", json=body, params={"agents_list": agent_id}
        )

    # ---- Agent Groups -------------------------------------------------

    async def list_groups(
        self,
        *,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List agent groups. Wazuh 4.x uses /groups not /agents/groups."""
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if search:
            params["search"] = search
        return await self._get("/groups", params=params)

    async def get_group(self, group_id: str) -> Dict[str, Any]:
        """Get agents belonging to a specific group."""
        data = await self._get("/groups", params={"search": group_id, "limit": 1})
        items = data.get("affected_items", []) if isinstance(data, dict) else data
        if not items:
            raise WazuhAPIError(404, f"Group {group_id} not found")
        return items[0]

    async def group_agents(
        self,
        group_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List agents in a specific group."""
        params: Dict[str, Any] = {
            "limit": limit,
            "offset": offset,
            "q": f"group={group_id}",
        }
        return await self._get("/agents", params=params)

    # ---- Per-Node Cluster Stats ---------------------------------------

    async def cluster_node_stats(self, node_id: str) -> Dict[str, Any]:
        """Get node stats — falls back to manager stats for single-node."""
        try:
            return await self._get(f"/cluster/{node_id}/stats")
        except WazuhAPIError:
            return await self.manager_stats()

    async def cluster_node_info(self, node_id: str) -> Dict[str, Any]:
        """Get configuration info for a specific cluster node."""
        return await self._get(f"/cluster/{node_id}/info")

    # ---- CDB Lists ----------------------------------------------------

    async def list_cdb_lists(
        self,
        *,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List CDB list files (uses /lists/files)."""
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if search:
            params["search"] = search
        return await self._get("/lists/files", params=params)

    async def get_cdb_list(
        self,
        list_name: str,
        *,
        search: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Read a CDB list file (uses /lists/files/{name})."""
        return await self._get(f"/lists/files/{list_name}")

    # ---- Manager Logs -------------------------------------------------

    async def manager_logs(
        self,
        *,
        category: Optional[str] = None,  # "all", "ossec", "api"
        search: Optional[str] = None,
        sort: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Retrieve Wazuh manager logs."""
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if category:
            params["category"] = category
        if search:
            params["search"] = search
        if sort:
            params["sort"] = sort
        return await self._get("/manager/logs", params=params)

    async def manager_logs_summary(self) -> Dict[str, Any]:
        """Get a summary of manager log categories."""
        return await self._get("/manager/logs/summary")
