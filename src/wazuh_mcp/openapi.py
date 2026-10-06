"""
OpenAPI 3.0 specification generator for Wazuh MCP Server.

Generates a complete OpenAPI spec from the registered MCP tools
and serves it at /docs (Swagger UI) and /openapi.json.

Usage (standalone):
    python -m wazuh_mcp.openapi

Or import:
    from wazuh_mcp.openapi import generate_openapi_spec, serve_openapi
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from wazuh_mcp import __version__

logger = logging.getLogger("wazuh-mcp.openapi")

# ---------------------------------------------------------------------------
# Tool schemas — parameter definitions for each tool
# ---------------------------------------------------------------------------

TOOL_SCHEMAS: Dict[str, Dict[str, Any]] = {
    # === Alerts ===
    "wazuh_list_alerts": {
        "summary": "Query Wazuh security alerts",
        "description": "Query alerts by severity, agent, rule ID, MITRE technique, and free-text search. Returns paginated results with summary statistics.",
        "parameters": {
            "agent_id": {
                "type": "string",
                "description": "Filter to specific agent ID (e.g., '001')",
            },
            "min_level": {
                "type": "integer",
                "description": "Minimum rule level (3-15). 12+ for critical only.",
            },
            "rule_id": {
                "type": "string",
                "description": "Filter by Wazuh rule ID (e.g., '5710')",
            },
            "mitre_id": {
                "type": "string",
                "description": "Filter by MITRE ATT&CK technique (e.g., 'T1110')",
            },
            "search": {
                "type": "string",
                "description": "Free-text search across alert fields",
            },
            "limit": {
                "type": "integer",
                "default": 50,
                "description": "Maximum alerts to return (1-500)",
            },
            "offset": {
                "type": "integer",
                "default": 0,
                "description": "Pagination offset",
            },
            "mode": {
                "type": "string",
                "enum": ["triage", "detail"],
                "description": "Output mode for token efficiency",
            },
            "compact_output": {
                "type": "boolean",
                "default": False,
                "description": "Enable token-efficient compact output",
            },
        },
        "tags": ["Alerts"],
    },
    "wazuh_get_alert": {
        "summary": "Get a single alert by ID",
        "description": "Fetch full contextual detail for a specific alert.",
        "parameters": {
            "alert_id": {
                "type": "string",
                "required": True,
                "description": "Alert ID to retrieve",
            },
        },
        "tags": ["Alerts"],
    },
    "wazuh_alert_summary": {
        "summary": "Summarize recent alerts",
        "description": "Aggregate view: severity distribution, top rules, MITRE coverage, top source IPs.",
        "parameters": {
            "hours_back": {
                "type": "integer",
                "default": 24,
                "description": "Hours to look back",
            },
            "min_level": {
                "type": "integer",
                "default": 7,
                "description": "Minimum alert level",
            },
        },
        "tags": ["Alerts"],
    },
    # === Hunting ===
    "wazuh_search_events": {
        "summary": "Search raw security events",
        "description": "Hunt for IOCs like IPs, file hashes, commands across all agents.",
        "parameters": {
            "search": {
                "type": "string",
                "required": True,
                "description": "Search term (IP, hash, command)",
            },
            "limit": {"type": "integer", "default": 50},
            "offset": {"type": "integer", "default": 0},
        },
        "tags": ["Hunting"],
    },
    "wazuh_query_fim": {
        "summary": "Query File Integrity Monitoring records",
        "parameters": {
            "agent_id": {"type": "string", "required": True},
            "file_path": {"type": "string", "description": "Filter by file path"},
            "event_type": {"type": "string", "enum": ["added", "modified", "deleted"]},
            "limit": {"type": "integer", "default": 100},
        },
        "tags": ["Hunting"],
    },
    "wazuh_query_vulnerabilities": {
        "summary": "Query vulnerability-detector findings",
        "parameters": {
            "agent_id": {"type": "string", "required": True},
            "cve": {"type": "string", "description": "Specific CVE ID"},
            "severity": {
                "type": "string",
                "enum": ["Critical", "High", "Medium", "Low"],
            },
            "limit": {"type": "integer", "default": 100},
        },
        "tags": ["Hunting"],
    },
    "wazuh_search_mitre": {
        "summary": "Search MITRE ATT&CK framework",
        "parameters": {
            "search": {
                "type": "string",
                "description": "Search techniques by name or keyword",
            },
            "technique_id": {
                "type": "string",
                "description": "Exact technique ID (e.g., 'T1547.001')",
            },
        },
        "tags": ["Hunting"],
    },
    # === Compliance ===
    "wazuh_sca_status": {
        "summary": "Get SCA compliance status for an agent",
        "parameters": {"agent_id": {"type": "string", "default": "000"}},
        "tags": ["Compliance"],
    },
    "wazuh_sca_checks": {
        "summary": "Get detailed SCA check results",
        "parameters": {
            "agent_id": {"type": "string", "required": True},
            "policy_id": {"type": "string"},
            "result": {"type": "string", "enum": ["passed", "failed"]},
        },
        "tags": ["Compliance"],
    },
    "wazuh_compliance_report": {
        "summary": "Generate fleet-wide compliance report",
        "parameters": {
            "agent_ids": {"type": "string", "description": "Comma-separated agent IDs"}
        },
        "tags": ["Compliance"],
    },
    # === Agents ===
    "wazuh_list_agents": {
        "summary": "List all Wazuh agents",
        "parameters": {
            "status": {
                "type": "string",
                "enum": ["active", "disconnected", "never_connected", "pending"],
            },
            "search": {"type": "string"},
            "limit": {"type": "integer", "default": 50},
        },
        "tags": ["Agents"],
    },
    "wazuh_get_agent": {
        "summary": "Get detailed agent information",
        "parameters": {"agent_id": {"type": "string", "required": True}},
        "tags": ["Agents"],
    },
    "wazuh_agent_health": {
        "summary": "Fleet-wide health overview",
        "parameters": {"stale_threshold_hours": {"type": "integer", "default": 24}},
        "tags": ["Agents"],
    },
    # === Groups ===
    "wazuh_list_groups": {
        "summary": "List agent groups",
        "tags": ["Groups"],
    },
    "wazuh_get_group": {
        "summary": "Get group details",
        "parameters": {"group_id": {"type": "string", "required": True}},
        "tags": ["Groups"],
    },
    # === Manager ===
    "wazuh_manager_stats": {
        "summary": "Manager daemon statistics",
        "parameters": {"daemon": {"type": "string"}},
        "tags": ["Manager"],
    },
    "wazuh_manager_logs": {
        "summary": "Retrieve manager logs",
        "parameters": {
            "category": {"type": "string", "enum": ["all", "ossec", "api"]},
            "search": {"type": "string"},
        },
        "tags": ["Manager"],
    },
    "wazuh_cluster_status": {
        "summary": "Cluster health status",
        "tags": ["Manager"],
    },
    "wazuh_rules_info": {
        "summary": "Search and list detection rules",
        "parameters": {
            "search": {"type": "string"},
            "level": {"type": "integer"},
            "pci": {"type": "string"},
            "gdpr": {"type": "string"},
            "hipaa": {"type": "string"},
            "nist_800_53": {"type": "string"},
            "mitre_technique": {"type": "string"},
        },
        "tags": ["Rules"],
    },
    # === Analysis ===
    "wazuh_rules_coverage_map": {
        "summary": "Generate compliance coverage matrix",
        "description": "Cross-reference rules against MITRE, NIST, PCI DSS, GDPR, HIPAA.",
        "parameters": {
            "framework": {"type": "string"},
            "min_level": {"type": "integer", "default": 5},
        },
        "tags": ["Analysis"],
    },
    "wazuh_vulnerability_heatmap": {
        "summary": "CVE severity heatmap across agents",
        "parameters": {
            "severity": {
                "type": "string",
                "enum": ["Critical", "High", "Medium", "Low"],
            }
        },
        "tags": ["Analysis"],
    },
    "wazuh_incident_timeline": {
        "summary": "Reconstruct attack timeline from an alert",
        "parameters": {
            "alert_id": {"type": "string", "required": True},
            "lookback_hours": {"type": "integer", "default": 24},
        },
        "tags": ["Analysis"],
    },
}


def generate_openapi_spec(
    title: str = "Wazuh MCP Server API",
    version: str = __version__,
    server_url: str = "http://localhost:8000",
) -> Dict[str, Any]:
    """
    Generate a complete OpenAPI 3.0 specification from tool schemas.

    Returns a dict ready for JSON serialization.
    """
    paths: Dict[str, Any] = {}

    for tool_name, schema in TOOL_SCHEMAS.items():
        params = schema.get("parameters", {})
        tags = schema.get("tags", ["General"])

        # Build OpenAPI path item
        path_item = {
            "post": {
                "operationId": tool_name,
                "summary": schema.get("summary", ""),
                "description": schema.get("description", ""),
                "tags": tags,
                "requestBody": {
                    "required": False,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": _params_to_openapi(params),
                                "required": [
                                    k
                                    for k, v in params.items()
                                    if v.get("required", False)
                                ],
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Successful response",
                        "content": {"application/json": {"schema": {"type": "object"}}},
                    },
                    "429": {"description": "Rate limit exceeded"},
                    "500": {"description": "Internal server error"},
                },
            }
        }
        paths[f"/tools/{tool_name}"] = path_item

    # Health endpoint
    paths["/health"] = {
        "get": {
            "operationId": "health_check",
            "summary": "Server health check",
            "tags": ["System"],
            "responses": {"200": {"description": "OK"}},
        }
    }

    # Metrics endpoint
    paths["/metrics"] = {
        "get": {
            "operationId": "prometheus_metrics",
            "summary": "Prometheus metrics endpoint",
            "tags": ["System"],
            "responses": {
                "200": {"description": "Prometheus text format"},
            },
        }
    }

    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": title,
            "version": version,
            "description": (
                "AI-powered security operations for Wazuh SIEM/XDR. "
                "28 MCP tools across 9 domains: alerts, hunting, compliance, "
                "agents, groups, lists, manager, response, and analysis."
            ),
            "contact": {
                "name": "Subhash Bharadwaj",
                "url": "https://github.com/Sbharadwaj05/wazuh-mcp-server",
            },
            "license": {"name": "MIT"},
        },
        "servers": [{"url": server_url, "description": "MCP Server"}],
        "tags": [
            {"name": "Alerts", "description": "Alert triage and investigation"},
            {"name": "Hunting", "description": "Threat hunting and IOC search"},
            {"name": "Compliance", "description": "SCA compliance assessment"},
            {"name": "Agents", "description": "Agent and fleet management"},
            {"name": "Groups", "description": "Agent group management"},
            {"name": "Manager", "description": "Manager, cluster, and rules"},
            {"name": "Analysis", "description": "Advanced security analysis"},
            {"name": "System", "description": "Health and metrics"},
        ],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "Wazuh API JWT token",
                }
            }
        },
        "security": [{"bearerAuth": []}],
    }

    return spec


def _params_to_openapi(params: Dict[str, Any]) -> Dict[str, Any]:
    """Convert tool parameter dicts to OpenAPI schema properties."""
    properties: Dict[str, Any] = {}
    for name, meta in params.items():
        prop: Dict[str, Any] = {}
        if "type" in meta:
            prop["type"] = meta["type"]
        if "description" in meta:
            prop["description"] = meta["description"]
        if "default" in meta:
            prop["default"] = meta["default"]
        if "enum" in meta:
            prop["enum"] = meta["enum"]
        properties[name] = prop
    return properties


def save_openapi_spec(path: str = "openapi.json") -> str:
    """Generate and save the OpenAPI spec to a file. Returns the path."""
    spec = generate_openapi_spec()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(spec, f, indent=2, ensure_ascii=False)
    logger.info("OpenAPI spec saved to %s", path)
    return path


# ---------------------------------------------------------------------------
# HTML for embedded Swagger UI
# ---------------------------------------------------------------------------

SWAGGER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Wazuh MCP Server — API Documentation</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
  <style>
    html { box-sizing: border-box; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin: 0; background: #fafafa; }
    .topbar { display: none; }
    .swagger-ui .info { margin: 20px 0; }
    .swagger-ui .info .title { font-size: 28px; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js" crossorigin></script>
  <script>
    SwaggerUIBundle({
      url: "/openapi.json",
      dom_id: "#swagger-ui",
      deepLinking: true,
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: "BaseLayout",
      defaultModelsExpandDepth: -1,
    });
  </script>
</body>
</html>
"""


def get_swagger_html() -> str:
    """Return the Swagger UI HTML page."""
    return SWAGGER_HTML


if __name__ == "__main__":
    # Generate and print the OpenAPI spec
    spec = generate_openapi_spec()
    print(json.dumps(spec, indent=2))
