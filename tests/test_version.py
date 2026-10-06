"""Every place that states the package version agrees with __version__."""

from __future__ import annotations

import json
import re
from pathlib import Path

from wazuh_mcp import __version__
from wazuh_mcp.openapi import generate_openapi_spec

ROOT = Path(__file__).resolve().parent.parent


def test_version_strings_agree():
    pyproject = re.search(
        r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M
    ).group(1)
    docker_label = re.search(
        r'image\.version="([^"]+)"', (ROOT / "Dockerfile").read_text()
    ).group(1)
    spec_file = json.loads((ROOT / "openapi.json").read_text())["info"]["version"]
    spec_generated = generate_openapi_spec()["info"]["version"]

    assert {pyproject, docker_label, spec_file, spec_generated} == {__version__}
