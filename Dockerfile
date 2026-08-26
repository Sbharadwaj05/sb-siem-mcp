# ---------------------------------------------------------------------------
# Multi-stage production Docker build for SB SIEM MCP
# ---------------------------------------------------------------------------
# Build:  docker build -t sb-siem-mcp:latest .
# Run:    docker run -e WAZUH_API_URL=https://wazuh:55000 -e WAZUH_USERNAME=admin -e WAZUH_PASSWORD=pass sb-siem-mcp
# ---------------------------------------------------------------------------

# ---- Stage 1: Builder ---------------------------------------------
FROM python:3.14-slim AS builder

WORKDIR /build

# Install build dependencies only
COPY pyproject.toml .
RUN pip install --no-cache-dir --user build setuptools wheel \
    && python -c "import tomllib; d = tomllib.load(open('pyproject.toml','rb')); print('\n'.join(d['project']['dependencies']))" > /tmp/deps.txt

# ---- Stage 2: Runtime ----------------------------------------------
FROM python:3.14-slim AS runtime

LABEL org.opencontainers.image.title="Wazuh MCP Server"
LABEL org.opencontainers.image.description="AI-powered security operations for Wazuh SIEM/XDR"
LABEL org.opencontainers.image.version="0.2.0"
LABEL org.opencontainers.image.source="https://github.com/Sbharadwaj05/sb-siem-mcp"

# Create non-root user
RUN groupadd -r wazuhmcp && useradd -r -g wazuhmcp -m -s /bin/bash wazuhmcp

WORKDIR /app

# Install runtime dependencies
COPY --from=builder /tmp/deps.txt /tmp/deps.txt
RUN pip install --no-cache-dir -r /tmp/deps.txt \
    && pip install --no-cache-dir mcp httpx python-dotenv

# Copy application code
COPY src/ ./src/
COPY pyproject.toml .

# Install the package
RUN pip install --no-cache-dir -e .

# Create audit log directory
RUN mkdir -p /home/wazuhmcp/.wazuh-mcp && chown -R wazuhmcp:wazuhmcp /home/wazuhmcp/.wazuh-mcp

# Switch to non-root user
USER wazuhmcp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# SSE mode by default (can override CMD for stdio)
EXPOSE 8000
ENV WAZUH_MCP_HOST=127.0.0.1
ENV WAZUH_MCP_PORT=8000

# Default: SSE transport. For Claude Desktop stdio mode, override with:
#   docker run ... sb-siem-mcp python -m wazuh_mcp.server
ENTRYPOINT ["python", "-c", "from wazuh_mcp.server import main_sse; main_sse()"]
