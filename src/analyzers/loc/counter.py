from pathlib import Path
from typing import Iterable
from .classifier import classify_line
from .models import FileLOC
from .exclusions import is_excluded

CODE_EXTENSIONS = (".py", ".js", ".ts", ".java")

def count_file(path: Path) -> FileLOC:
    total = code = blank = comment = 0

    suffix = path.suffix.lower()
    for line in path.read_text(errors="ignore").splitlines():
        total += 1
        kind = classify_line(line, suffix)
        if kind == "blank":
            blank += 1
        elif kind == "comment":
            comment += 1
        else:
            code += 1

    return FileLOC(
        path=str(path),
        total_lines=total,
        code_lines=code,
        blank_lines=blank,
        comment_lines=comment,
    )

def count_repository(repo_path: Path, exclude: Iterable[str] = ()):
    results = []
    for file in repo_path.rglob("*"):
        if not file.is_file():
            continue
        if is_excluded(file, exclude):
            continue
        if file.suffix.lower() in CODE_EXTENSIONS:
            results.append(count_file(file))
    return results
