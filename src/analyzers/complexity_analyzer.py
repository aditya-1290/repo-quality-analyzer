from .base import BaseAnalyzer, AnalyzerResult

COMPLEXITY_TOKENS = ("if ", "for ", "while ", "case ", "except ")

class ComplexityAnalyzer(BaseAnalyzer):
    def analyze(self) -> AnalyzerResult:
        complexity = 0

        for file in self.repo_path.rglob("*.py"):
            content = self._safe_read(file)
            for token in COMPLEXITY_TOKENS:
                complexity += content.count(token)

        score = max(0.0, 1.0 - (complexity / 5000))

        return AnalyzerResult(
            name="complexity",
            score=score,
            details={"complexity_tokens": complexity}
        )
