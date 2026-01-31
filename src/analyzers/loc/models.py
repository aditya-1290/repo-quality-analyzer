from dataclasses import dataclass, field
from typing import Dict, List

@dataclass
class FileLOC:
    path: str
    total_lines: int
    code_lines: int
    blank_lines: int
    comment_lines: int

@dataclass
class LOCAggregate:
    files: List[FileLOC] = field(default_factory=list)

    @property
    def total_files(self) -> int:
        return len(self.files)

    @property
    def total_lines(self) -> int:
        return sum(f.total_lines for f in self.files)

    @property
    def code_lines(self) -> int:
        return sum(f.code_lines for f in self.files)

    @property
    def blank_lines(self) -> int:
        return sum(f.blank_lines for f in self.files)

    @property
    def comment_lines(self) -> int:
        return sum(f.comment_lines for f in self.files)

    def as_dict(self) -> Dict[str, int]:
        return {
            "files": self.total_files,
            "total_lines": self.total_lines,
            "code_lines": self.code_lines,
            "blank_lines": self.blank_lines,
            "comment_lines": self.comment_lines,
        }
