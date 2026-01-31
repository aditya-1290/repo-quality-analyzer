from pathlib import Path
from .filters import is_test_file, is_source_file
from .models import FileEntry

def index_files(repo_path: Path):
    entries = []
    for p in repo_path.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(repo_path))
            entries.append(
                FileEntry(
                    path=p,
                    is_test=is_test_file(rel),
                    is_source=is_source_file(rel)
                )
            )
    return entries
