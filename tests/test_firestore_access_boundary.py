"""ARCHITECTURE.md section 3, rule 2: "Every Firestore access goes
through data/scope_store.py. Direct client use anywhere else fails CI."
data/scope_store.py's own docstring already claims this test exists -
this is that test.

data/scope_store.py is the sole exception, by design - it IS the
Firestore access layer. infra/ and seed/ are also exempt: bootstrap/seed
scripts touch Firestore before any registry identity could plausibly
have scope to do it through the normal authenticated path (that's
exactly what scope_store.bootstrap_write/bootstrap_registry_write exist
for), and infra/init_firestore.py's own pre-write existence check
documents exactly why it reaches into scope_store's internals directly
rather than through the public API.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXEMPT_DIRS = {"infra", "seed", "tests", ".venv"}
EXEMPT_FILES = {REPO_ROOT / "data" / "scope_store.py"}

_FORBIDDEN_PATTERNS = [
    re.compile(r"^\s*from\s+google\.cloud\s+import\s+firestore\b"),
    re.compile(r"^\s*import\s+google\.cloud\.firestore\b"),
    re.compile(r"firestore\.Client\s*\("),
]


def _python_files() -> list[Path]:
    files = []
    for path in REPO_ROOT.rglob("*.py"):
        if path in EXEMPT_FILES:
            continue
        if any(part in EXEMPT_DIRS for part in path.relative_to(REPO_ROOT).parts):
            continue
        files.append(path)
    return files


def test_no_module_outside_scope_store_touches_firestore_directly():
    violations = []
    for path in _python_files():
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if any(pattern.search(line) for pattern in _FORBIDDEN_PATTERNS):
                violations.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}")

    assert not violations, (
        "Direct Firestore client usage found outside data/scope_store.py - "
        "every read/write must go through scope_store.read()/write()/query() "
        "so scope enforcement and tenant isolation actually apply:\n"
        + "\n".join(violations)
    )


def test_this_test_actually_catches_something():
    scope_store_file = REPO_ROOT / "data" / "scope_store.py"
    assert scope_store_file.exists()
    content = scope_store_file.read_text()
    assert "from google.cloud import firestore" in content

    synthetic_violation = "from google.cloud import firestore"
    assert any(p.search(synthetic_violation) for p in _FORBIDDEN_PATTERNS)
