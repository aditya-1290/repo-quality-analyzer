from pathlib import Path
from .base import BaseAnalyzer, AnalyzerResult

DEPENDENCY_FILES = (
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "pom.xml"
)

class DependencyAnalyzer(BaseAnalyzer):
    def analyze(self) -> AnalyzerResult:
        deps = {}

        for fname in DEPENDENCY_FILES:
            path = self.repo_path / fname
            if path.exists():
                content = self._safe_read(path)
                deps[fname] = len(content.splitlines())

        score = min(1.0, sum(deps.values()) / 200)

        return AnalyzerResult(
            name="dependencies",
            score=score,
            details=deps
        )
