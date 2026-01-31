from pathlib import Path
from .file_index import index_files
from .models import ScanResult

def scan_repository(path: str) -> ScanResult:
    repo = Path(path).resolve()
    if not repo.exists():
        raise ValueError("Repository path does not exist")

    files = index_files(repo)
    return ScanResult(files=files)
