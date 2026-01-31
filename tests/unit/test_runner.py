import tempfile
from pathlib import Path
from src.cli.runner import run_analysis

def test_run_analysis_on_temp_repo():
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        (repo / ".git").mkdir()  # fake git repo marker
        result = run_analysis(str(repo))
        assert result["repo"] == repo.name
        assert result["status"] == "analyzed"
