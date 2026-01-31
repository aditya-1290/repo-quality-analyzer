import subprocess
import sys
import tempfile
from pathlib import Path

def test_cli_analyze_runs():
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        (repo / ".git").mkdir()

        cmd = [
            sys.executable,
            "-m",
            "src.cli.main",
            "analyze",
            str(repo)
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0
