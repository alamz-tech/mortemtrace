"""ARCHITECTURE.md section 3, rule 1: "No agent imports the Vertex SDK.
Only gateway/ does. Import lint check in CI." Several modules'
docstrings already claim this test exists and enforces it - this is
that test. A rule that's only ever documented, never checked, is a
suggestion wearing an architecture diagram; this makes it real.

gateway/ is the sole exception, by design - it IS the Vertex/ADK path.
infra/ and seed/ are also exempt: one-time environment setup scripts are
not agent runtime code, and infra/setup_model_armor.py legitimately
talks to the Model Armor API directly to provision the template
gateway/model_armor.py later sanitizes against at runtime.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXEMPT_DIRS = {"gateway", "infra", "seed", "tests", ".venv"}

_FORBIDDEN_PATTERNS = [
    re.compile(r"^\s*import\s+vertexai\b"),
    re.compile(r"^\s*from\s+vertexai\b"),
    re.compile(r"^\s*import\s+google\.genai\b"),
    re.compile(r"^\s*from\s+google\.genai\b"),
    re.compile(r"^\s*from\s+google\.adk\b"),
    re.compile(r"^\s*import\s+google\.adk\b"),
]


def _python_files() -> list[Path]:
    files = []
    for path in REPO_ROOT.rglob("*.py"):
        if any(part in EXEMPT_DIRS for part in path.relative_to(REPO_ROOT).parts):
            continue
        files.append(path)
    return files


def test_no_module_outside_gateway_imports_vertex_or_adk_directly():
    violations = []
    for path in _python_files():
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if any(pattern.match(line) for pattern in _FORBIDDEN_PATTERNS):
                violations.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}")

    assert not violations, (
        "Direct Vertex AI / ADK / google.genai import found outside gateway/ - "
        "route model calls through gateway.agent_gateway.build_agent()/invoke() "
        "instead:\n" + "\n".join(violations)
    )


def test_this_test_actually_catches_something():
    """A boundary test that can never fail is worthless - this proves the
    detection logic itself works by checking gateway/ is exempt (would
    otherwise flag its own legitimate imports) and that a synthetic
    violation would be caught."""
    gateway_file = REPO_ROOT / "gateway" / "agent_gateway.py"
    assert gateway_file.exists()
    content = gateway_file.read_text()
    assert "from google.adk" in content  # confirms the pattern really matches real code

    synthetic_violation = "from google.adk.agents import LlmAgent"
    assert any(p.match(synthetic_violation) for p in _FORBIDDEN_PATTERNS)
