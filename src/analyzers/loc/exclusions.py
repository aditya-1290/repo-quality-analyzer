from pathlib import Path
from typing import Iterable

DEFAULT_EXCLUDES = (
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
)

def is_excluded(path: Path, extra: Iterable[str] = ()) -> bool:
    all_rules = set(DEFAULT_EXCLUDES).union(extra)
    for part in path.parts:
        if part in all_rules:
            return True
    return False
