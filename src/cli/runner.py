import json
from pathlib import Path

def run_analysis(path: str) -> dict:
    repo = Path(path).resolve()
    if not repo.exists():
        raise FileNotFoundError(f"Repository not found: {repo}")

    # placeholder for real analyzers (will be expanded later)
    return {
        "repo": repo.name,
        "status": "analyzed",
        "metrics": {
            "files": 0,
            "tests": 0,
            "ci": False
        }
    }

def render(result: dict, as_json: bool) -> str:
    return json.dumps(result, indent=2) if as_json else str(result)
