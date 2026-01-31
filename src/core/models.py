from dataclasses import dataclass
from pathlib import Path
from typing import List

@dataclass
class FileEntry:
    path: Path
    is_test: bool
    is_source: bool

@dataclass
class ScanResult:
    files: List[FileEntry]

    @property
    def total_files(self) -> int:
        return len(self.files)

    @property
    def test_files(self) -> int:
        return sum(1 for f in self.files if f.is_test)

    @property
    def source_files(self) -> int:
        return sum(1 for f in self.files if f.is_source)
