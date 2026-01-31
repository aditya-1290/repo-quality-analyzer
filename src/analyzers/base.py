from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any

@dataclass
class AnalyzerResult:
    name: str
    score: float
    details: Dict[str, Any]

class BaseAnalyzer(ABC):
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path

    @abstractmethod
    def analyze(self) -> AnalyzerResult:
        pass

    def _safe_read(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""
