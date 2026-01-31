import subprocess
import time
from pathlib import Path
from datetime import datetime

import pytest

from src.git.git_history_engine import (
    find_git_repository_root,
    validate_git_repository,
    is_git_available,
    run_git_command,
    parse_git_log_line,
    get_commit_log,
    normalize_authors,
    group_commits_by_author,
    get_commit_stats,
    attach_commit_stats,
    bucket_commits_by_day,
    bucket_commits_by_month,
    compute_commit_frequency,
    compute_author_contributions,
    compute_bus_factor,
    detect_inactivity,
    analyze_commit_messages,
    compute_history_score,
    extract_file_level_changes,
    aggregate_file_impact_across_commits,
    compute_churn_metrics,
    analyze_author_time_distribution,
    detect_merge_commits,
    build_git_history_report,
    build_extended_git_history_report,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """
    Create a temporary git repository with multiple commits.
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    subprocess.run(["git", "init"], cwd=repo, check=True)

    file1 = repo / "a.txt"
    file1.write_text("one\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "initial commit"],
        cwd=repo,
        check=True,
    )

    time.sleep(1)

    file1.write_text("one\ntwo\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "add second line"],
        cwd=repo,
        check=True,
    )

    file2 = repo / "b.txt"
    file2.write_text("alpha\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "add new file"],
        cwd=repo,
        check=True,
    )

    return repo


# =============================================================================
# Repository discovery & validation
# =============================================================================

def test_git_available():
    assert is_git_available() is True


def test_find_git_repository_root(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    assert repo_info.root_path == git_repo
    assert repo_info.git_dir.exists()


def test_validate_git_repository(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    validate_git_repository(repo_info)


# =============================================================================
# Git command execution
# =============================================================================

def test_run_git_command(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    output = run_git_command(repo_info, ["rev-parse", "HEAD"])
    assert len(output) > 0


# =============================================================================
# Commit log parsing
# =============================================================================

def test_parse_git_log_line():
    line = "abc123|John Doe|john@example.com|1700000000|commit message"
    record = parse_git_log_line(line)

    assert record is not None
    assert record.author.email == "john@example.com"
    assert isinstance(record.authored_date, datetime)


def test_get_commit_log(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = get_commit_log(repo_info)

    assert len(commits) >= 3
    assert all(c.commit_hash for c in commits)


# =============================================================================
# Author normalization & grouping
# =============================================================================

def test_normalize_authors(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = get_commit_log(repo_info)

    normalized = normalize_authors(commits)
    assert normalized[0].author.email == commits[0].author.email.lower()


def test_group_commits_by_author(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = normalize_authors(get_commit_log(repo_info))

    grouped = group_commits_by_author(commits)
    assert len(grouped) >= 1
    for commits in grouped.values():
        assert len(commits) > 0


# =============================================================================
# Commit statistics
# =============================================================================

def test_get_commit_stats(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = get_commit_log(repo_info)

    stats = get_commit_stats(repo_info, commits[0].commit_hash)
    assert stats.files_changed >= 0
    assert stats.insertions >= 0


def test_attach_commit_stats(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = get_commit_log(repo_info)

    enriched = attach_commit_stats(repo_info, commits)
    assert enriched[0].stats is not None


# =============================================================================
# Timeline & frequency
# =============================================================================

def test_bucket_commits_by_day(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = get_commit_log(repo_info)

    buckets = bucket_commits_by_day(commits)
    assert len(buckets) >= 1


def test_bucket_commits_by_month(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = get_commit_log(repo_info)

    buckets = bucket_commits_by_month(commits)
    assert len(buckets) >= 1


def test_compute_commit_frequency(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = get_commit_log(repo_info)

    freq = compute_commit_frequency(commits)
    assert freq["total_commits"] >= 1
    assert freq["commits_per_day"] >= 0.0


# =============================================================================
# Contribution & risk analysis
# =============================================================================

def test_compute_author_contributions(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = attach_commit_stats(
        repo_info,
        get_commit_log(repo_info),
    )

    contrib = compute_author_contributions(commits)
    assert len(contrib) >= 1


def test_compute_bus_factor(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = attach_commit_stats(
        repo_info,
        get_commit_log(repo_info),
    )

    contrib = compute_author_contributions(commits)
    bus = compute_bus_factor(contrib)

    assert bus["bus_factor"] >= 1


def test_detect_inactivity_active_repo(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = get_commit_log(repo_info)

    inactivity = detect_inactivity(commits)
    assert inactivity["inactive"] is False


# =============================================================================
# Commit message quality
# =============================================================================

def test_analyze_commit_messages(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = get_commit_log(repo_info)

    quality = analyze_commit_messages(commits)
    assert quality["total_messages"] >= 1
    assert quality["meaningful_ratio"] >= 0.0


# =============================================================================
# Churn & file impact
# =============================================================================

def test_extract_file_level_changes(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = get_commit_log(repo_info)

    impacts = extract_file_level_changes(
        repo_info,
        commits[0].commit_hash,
    )
    assert isinstance(impacts, list)


def test_aggregate_file_impact_across_commits(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = get_commit_log(repo_info)

    impacts = aggregate_file_impact_across_commits(
        repo_info,
        commits,
    )
    assert isinstance(impacts, dict)


def test_compute_churn_metrics(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = get_commit_log(repo_info)

    impacts = aggregate_file_impact_across_commits(
        repo_info,
        commits,
    )
    churn = compute_churn_metrics(impacts)

    assert churn["files"] >= 0


# =============================================================================
# Time distribution & merges
# =============================================================================

def test_analyze_author_time_distribution(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = get_commit_log(repo_info)

    dist = analyze_author_time_distribution(commits)
    assert len(dist) >= 1


def test_detect_merge_commits(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    commits = get_commit_log(repo_info)

    merges = detect_merge_commits(commits)
    assert "merge_commits" in merges


# =============================================================================
# Report builders
# =============================================================================

def test_build_git_history_report(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    report = build_git_history_report(repo_info)

    assert "summary" in report
    assert "authors" in report
    assert "score" in report


def test_build_extended_git_history_report(git_repo: Path):
    repo_info = find_git_repository_root(git_repo)
    report = build_extended_git_history_report(repo_info)

    assert "churn" in report
    assert "bus_factor" in report
    assert "author_time_distribution" in report
