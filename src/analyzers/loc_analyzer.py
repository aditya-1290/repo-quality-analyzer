from pathlib import Path
from typing import Dict
from .base import BaseAnalyzer, AnalyzerResult

CODE_EXTENSIONS = (
    ".py", ".js", ".ts", ".java", ".go", ".rs",
    ".cpp", ".c", ".h"
)

class LOCAnalyzer(BaseAnalyzer):
    def analyze(self) -> AnalyzerResult:
        totals: Dict[str, int] = {
            "files": 0,
            "lines": 0,
            "code_lines": 0,
            "blank_lines": 0
        }

        for file in self.repo_path.rglob("*"):
            if file.suffix.lower() in CODE_EXTENSIONS and file.is_file():
                totals["files"] += 1
                content = self._safe_read(file).splitlines()

                for line in content:
                    totals["lines"] += 1
                    if not line.strip():
                        totals["blank_lines"] += 1
                    else:
                        totals["code_lines"] += 1

        score = min(1.0, totals["code_lines"] / 10000) if totals["code_lines"] else 0.0

        return AnalyzerResult(
            name="loc",
            score=score,
            details=totals
        )
