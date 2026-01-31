from .base import BaseAnalyzer, AnalyzerResult

CI_PATHS = (
    ".github/workflows",
    ".gitlab-ci.yml",
    ".travis.yml",
    "Jenkinsfile"
)

class CIAnalyzer(BaseAnalyzer):
    def analyze(self) -> AnalyzerResult:
        found = []

        for path in CI_PATHS:
            if (self.repo_path / path).exists():
                found.append(path)

        return AnalyzerResult(
            name="ci",
            score=1.0 if found else 0.0,
            details={"ci_files": found}
        )
