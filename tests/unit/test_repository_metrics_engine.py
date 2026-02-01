import subprocess
import time
from pathlib import Path
from datetime import datetime

import pytest

from src.metrics.repository_metrics_engine import (
    StructuralMetrics,
    ActivityMetrics,
    QualitySignals,
    RepositoryMetrics,
    MetricThresholds,
    STRICT_PRESET,
    RELAXED_PRESET,
    compute_structural_metrics,
    compute_activity_metrics,
    compute_quality_signals,
    compute_repository_metrics,
    clamp,
    normalize_ratio,
    normalize_inverse,
    score_activity,
    score_quality,
    score_structure,
    compute_composite_score,
    detect_risk_flags,
    compare_repositories,
    build_metrics_report,
    build_compact_metrics_report,
    export_metrics_to_json,
    export_metrics_to_markdown,
    analyze_repository,
    analyze_repository_compact,
    grade_score,
    compute_activity_trend,
    compute_churn_stability,
    compute_bus_factor_risk,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """
    Create a temporary git repository with files, tests, and history.
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    subprocess.run(["git", "init"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "dev@test.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Dev User"], cwd=repo, check=True)

    # structure
    src = repo / "src"
    tests = repo / "tests"
    src.mkdir()
    tests.mkdir()

    (repo / "README.md").write_text("# Repo\n", encoding="utf-8")
    (src / "a.py").write_text("print('a')\n", encoding="utf-8")
    (tests / "test_a.py").write_text("def test_a(): assert True\n", encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=repo, check=True)

    time.sleep(1)

    (src / "a.py").write_text("print('a')\nprint('b')\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "extend module"], cwd=repo, check=True)

    return repo


# =============================================================================
# Utility helpers
# =============================================================================

def test_clamp():
    assert clamp(1.5) == 1.0
    assert clamp(-1.0) == 0.0
    assert clamp(0.5) == 0.5


def test_normalize_ratio():
    assert normalize_ratio(1, 2) == 0.5
    assert normalize_ratio(1, 0) == 0.0


def test_normalize_inverse():
    assert normalize_inverse(0, scale=10) == 1.0
    assert normalize_inverse(10, scale=10) == 0.0


# =============================================================================
# Structural metrics
# =============================================================================

def test_compute_structural_metrics(repo: Path):
    metrics = compute_structural_metrics(repo)

    assert isinstance(metrics, StructuralMetrics)
    assert metrics.total_lines > 0
    assert metrics.files_counted > 0
    assert "python" in metrics.languages


# =============================================================================
# Activity metrics
# =============================================================================

def test_compute_activity_metrics(repo: Path):
    metrics = compute_activity_metrics(repo)

    assert isinstance(metrics, ActivityMetrics)
    assert metrics.total_commits >= 1
    assert metrics.commits_per_day >= 0.0


# =============================================================================
# Quality signals
# =============================================================================

def test_compute_quality_signals(repo: Path):
    quality = compute_quality_signals(repo)

    assert isinstance(quality, QualitySignals)
    assert quality.bus_factor >= 1
    assert 0.0 <= quality.meaningful_commit_ratio <= 1.0


# =============================================================================
# Repository orchestration
# =============================================================================

def test_compute_repository_metrics(repo: Path):
    metrics = compute_repository_metrics(repo, include_raw=True)

    assert isinstance(metrics, RepositoryMetrics)
    assert metrics.structural.total_lines > 0
    assert metrics.activity.total_commits > 0
    assert "filesystem_quick" in metrics.raw


# =============================================================================
# Scoring
# =============================================================================

def test_score_activity(repo: Path):
    activity = compute_activity_metrics(repo)
    scored = score_activity(activity)

    assert 0.0 <= scored["score"] <= 1.0


def test_score_quality(repo: Path):
    quality = compute_quality_signals(repo)
    scored = score_quality(quality)

    assert 0.0 <= scored["score"] <= 1.0


def test_score_structure(repo: Path):
    structural = compute_structural_metrics(repo)
    scored = score_structure(structural)

    assert 0.0 <= scored["score"] <= 1.0


def test_compute_composite_score(repo: Path):
    metrics = compute_repository_metrics(repo)
    composite = compute_composite_score(
        metrics.structural,
        metrics.activity,
        metrics.quality,
    )

    assert "total_score" in composite
    assert 0.0 <= composite["total_score"] <= 1.0


# =============================================================================
# Risk & comparison
# =============================================================================

def test_detect_risk_flags(repo: Path):
    metrics = compute_repository_metrics(repo)
    flags = detect_risk_flags(metrics.activity, metrics.quality)

    assert isinstance(flags, list)


def test_compare_repositories(repo: Path):
    metrics_a = compute_repository_metrics(repo)
    metrics_b = compute_repository_metrics(repo)

    comparison = compare_repositories(metrics_a, metrics_b)
    assert "total_score_diff" in comparison


# =============================================================================
# Reports
# =============================================================================

def test_build_metrics_report(repo: Path):
    metrics = compute_repository_metrics(repo)
    report = build_metrics_report(metrics, preset=RELAXED_PRESET)

    assert "scores" in report
    assert "risk_flags" in report


def test_build_compact_metrics_report(repo: Path):
    metrics = compute_repository_metrics(repo)
    report = build_compact_metrics_report(metrics)

    assert "score" in report
    assert "files" in report


# =============================================================================
# Exports
# =============================================================================

def test_export_metrics_to_json(repo: Path):
    metrics = compute_repository_metrics(repo)
    report = build_metrics_report(metrics)

    json_str = export_metrics_to_json(report)
    assert json_str.startswith("{")


def test_export_metrics_to_markdown(repo: Path):
    metrics = compute_repository_metrics(repo)
    report = build_metrics_report(metrics)

    md = export_metrics_to_markdown(report)
    assert "# Repository Metrics Report" in md


# =============================================================================
# Presets & orchestration
# =============================================================================

def test_analyze_repository(repo: Path):
    report = analyze_repository(repo, preset_name="relaxed")

    assert "scores" in report
    assert report["preset"] == "relaxed"


def test_analyze_repository_compact(repo: Path):
    report = analyze_repository_compact(repo)

    assert "score" in report
    assert report["files"] > 0


# =============================================================================
# Grading & classification helpers
# =============================================================================

def test_grade_score():
    assert grade_score(0.9) == "A"
    assert grade_score(0.75) == "B"
    assert grade_score(0.6) == "C"
    assert grade_score(0.3) == "D"


def test_activity_trend():
    assert compute_activity_trend(0.2) == "high"
    assert compute_activity_trend(0.05) == "moderate"
    assert compute_activity_trend(0.0) == "low"


def test_churn_stability():
    assert compute_churn_stability(100) == "stable"
    assert compute_churn_stability(400) == "moderate"
    assert compute_churn_stability(900) == "volatile"


def test_bus_factor_risk():
    assert compute_bus_factor_risk(5) == "low"
    assert compute_bus_factor_risk(2) == "medium"
    assert compute_bus_factor_risk(1) == "high"
