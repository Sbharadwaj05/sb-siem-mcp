"""
Async OpenSearch client for the Wazuh Indexer.

Queries the Wazuh Indexer directly for alerts, events, vulnerabilities,
and other indexed data that is NOT available through the Wazuh REST API.

Configure via:
  WAZUH_INDEXER_URL  — https://your-indexer:9200 (default: same as API host)
  WAZUH_INDEXER_USER — indexer username (default: admin)
  WAZUH_INDEXER_PASS — indexer password
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional

import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("wazuh-mcp.indexer")

# Default to same host as Wazuh API, port 9200
DEFAULT_INDEXER_URL = os.getenv(
    "WAZUH_INDEXER_URL",
    os.getenv("WAZUH_API_URL", "https://localhost:55000").replace(":55000", ":9200"),
)
DEFAULT_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
DEFAULT_INDEXER_PASS = os.getenv(
    "WAZUH_INDEXER_PASS", os.getenv("WAZUH_PASSWORD", "admin")
)
DEFAULT_INSECURE = os.getenv("WAZUH_INSECURE", "false").lower() == "true"

# Lucene special characters that must be escaped in query_string queries.
# See: https://lucene.apache.org/core/2_9_4/queryparsersyntax.html#Escaping
_LUCENE_SPECIAL = re.compile(r"([+\-!(){}\[\]^\"~*?:\\/]|&&|\|\|)")


def escape_lucene(value: str) -> str:
    """Escape Lucene query_string special characters to prevent injection."""
    return _LUCENE_SPECIAL.sub(r"\\\1", value)


class IndexerClient:
    """
    Async client for the Wazuh Indexer (OpenSearch).

    Queries alert, vulnerability, and event indices directly.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_INDEXER_URL,
        username: str = DEFAULT_INDEXER_USER,
        password: str = DEFAULT_INDEXER_PASS,
        insecure: bool = DEFAULT_INSECURE,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(30.0),
            verify=not insecure,
        )
        self._auth = (username, password)

    async def close(self) -> None:
        await self._client.aclose()

    async def _search(
        self,
        index: str,
        query: Dict[str, Any],
        size: int = 50,
        from_: int = 0,
        sort: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        """Execute an OpenSearch query and return normalized results."""
        body: Dict[str, Any] = {
            "size": size,
            "from": from_,
            "query": query,
        }
        if sort:
            body["sort"] = sort

        resp = await self._client.post(
            f"/{index}/_search",
            json=body,
            auth=self._auth,
        )
        resp.raise_for_status()
        data = resp.json()

        hits = data.get("hits", {})
        total = hits.get("total", {})
        total_value = total.get("value", 0) if isinstance(total, dict) else total

        items = [
            {"_id": h.get("_id", ""), **h.get("_source", {})}
            for h in hits.get("hits", [])
        ]

        return {
            "affected_items": items,
            "total_affected_items": total_value,
        }

    # ---- Alerts -------------------------------------------------------

    async def list_alerts(
        self,
        *,
        min_level: Optional[int] = None,
        agent_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        search: Optional[str] = None,
        mitre_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        sort: str = "desc",
    ) -> Dict[str, Any]:
        """Query alerts from the wazuh-alerts-* index."""
        must: List[Dict] = []

        if min_level is not None:
            must.append({"range": {"rule.level": {"gte": min_level}}})
        if agent_id:
            must.append({"term": {"agent.id": agent_id}})
        if rule_id:
            must.append({"term": {"rule.id": rule_id}})
        if mitre_id:
            must.append({"term": {"rule.mitre.id": mitre_id}})
        if search:
            must.append({"query_string": {"query": escape_lucene(search)}})

        query: Dict[str, Any] = {"bool": {"must": must}} if must else {"match_all": {}}

        return await self._search(
            "wazuh-alerts-*",
            query,
            size=min(limit, 500),
            from_=offset,
            sort=[{"timestamp": {"order": sort}}],
        )

    async def get_alert(self, alert_id: str) -> Dict[str, Any]:
        """Fetch a single alert by its Wazuh alert ID or OpenSearch _id."""
        # Try as OpenSearch doc _id first
        resp = await self._client.get(
            f"/wazuh-alerts-*/_doc/{alert_id}",
            auth=self._auth,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("found"):
                return data.get("_source", {})
        # Fallback: search by the alert's 'id' field
        result = await self._search(
            "wazuh-alerts-*",
            {"term": {"id": alert_id}},
            size=1,
        )
        items = result.get("affected_items", [])
        if items:
            return items[0]
        raise ValueError(f"Alert {alert_id} not found in indexer")

    # ---- Vulnerabilities ----------------------------------------------

    async def vulnerabilities(
        self,
        *,
        agent_id: Optional[str] = None,
        severity: Optional[str] = None,
        cve: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Query vulnerabilities from wazuh-states-vulnerabilities-*."""
        must: List[Dict] = []

        if agent_id:
            must.append({"term": {"agent.id": agent_id}})
        # Keyword fields: the index stores "High" and "CVE-..."; callers
        # send whatever case the model chose.
        if severity:
            must.append(
                {"term": {"vulnerability.severity": {"value": severity, "case_insensitive": True}}}
            )
        if cve:
            must.append({"term": {"vulnerability.id": {"value": cve, "case_insensitive": True}}})
        if search:
            must.append({"query_string": {"query": escape_lucene(search)}})

        query: Dict[str, Any] = {"bool": {"must": must}} if must else {"match_all": {}}

        return await self._search(
            "wazuh-states-vulnerabilities-*",
            query,
            size=min(limit, 500),
            from_=offset,
        )

    # ---- Events / FIM from indexer ------------------------------------

    async def search_events(
        self,
        *,
        search: Optional[str] = None,
        index: str = "wazuh-alerts-*",
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Generic search across Wazuh indices."""
        query: Dict[str, Any] = (
            {"query_string": {"query": escape_lucene(search)}}
            if search
            else {"match_all": {}}
        )
        return await self._search(index, query, size=min(limit, 500), from_=offset)
