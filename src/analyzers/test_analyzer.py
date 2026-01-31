from pathlib import Path
from .base import BaseAnalyzer, AnalyzerResult

TEST_MARKERS = ("test_", "_test", "/tests/", "__tests__", ".spec.", ".test.")

class TestAnalyzer(BaseAnalyzer):
    def analyze(self) -> AnalyzerResult:
        test_files = 0
        source_files = 0

        for file in self.repo_path.rglob("*"):
            if not file.is_file():
                continue

            rel = str(file.relative_to(self.repo_path)).lower()
            if file.suffix == ".py":
                if any(m in rel for m in TEST_MARKERS):
                    test_files += 1
                else:
                    source_files += 1

        ratio = test_files / max(1, source_files)

        return AnalyzerResult(
            name="tests",
            score=min(1.0, ratio),
            details={
                "test_files": test_files,
                "source_files": source_files,
                "ratio": ratio
            }
        )
