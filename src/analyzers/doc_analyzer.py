from .base import BaseAnalyzer, AnalyzerResult

DOC_FILES = ("README.md", "CONTRIBUTING.md", "CHANGELOG.md")

class DocumentationAnalyzer(BaseAnalyzer):
    def analyze(self) -> AnalyzerResult:
        docs = {}
        for name in DOC_FILES:
            path = self.repo_path / name
            if path.exists():
                docs[name] = len(self._safe_read(path).splitlines())

        score = min(1.0, sum(docs.values()) / 300)

        return AnalyzerResult(
            name="documentation",
            score=score,
            details=docs
        )
