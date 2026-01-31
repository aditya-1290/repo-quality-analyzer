from pathlib import Path

COMMENT_PREFIXES = {
    ".py": "#",
    ".js": "//",
    ".ts": "//",
    ".java": "//",
}

def classify_line(line: str, suffix: str) -> str:
    stripped = line.strip()
    if not stripped:
        return "blank"

    prefix = COMMENT_PREFIXES.get(suffix)
    if prefix and stripped.startswith(prefix):
        return "comment"

    return "code"
