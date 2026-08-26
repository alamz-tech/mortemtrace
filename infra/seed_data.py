"""Thin wrapper: `python -m infra.seed_data` seeds synthetic demo data.
The actual generator lives in seed/generate.py, per ARCHITECTURE.md
section 7's repo layout (a top-level seed/ directory, separate from
infra/'s one-time setup scripts)."""
from __future__ import annotations

from seed.generate import main

if __name__ == "__main__":
    main()
