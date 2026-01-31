"""
Git History Analysis Engine

This module provides utilities for extracting and analyzing git repository
history. It focuses on commit metadata, authorship, timelines, and change
frequency, serving as a foundation for repository quality analysis.
"""

from __future__ import annotations

import os
import subprocess
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime


LOGGER_NAME = "repo_quality.git_history"
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(logging.INFO)


# =============================================================================
# Exceptions
# =============================================================================

class GitHistoryError(Exception):
    """Base exception for git history analysis."""


class GitRepositoryNotFoundError(GitHistoryError):
    """Raised when a git repository cannot be located."""


class GitCommandError(GitHistoryError):
    """Raised when a git command execution fails."""


# =============================================================================
# Data models
# =============================================================================

@dataclass
class CommitAuthor:
    name: str
    email: str

    def normalized(self) -> "CommitAuthor":
        """
        Normalize author fields for comparison.
        """
        return CommitAuthor(
            name=self.name.strip().lower(),
            email=self.email.strip().lower(),
        )


@dataclass
class CommitStats:
    files_changed: int
    insertions: int
    deletions: int


@dataclass
class CommitRecord:
    commit_hash: str
    author: CommitAuthor
    authored_date: datetime
    message: str
    stats: Optional[CommitStats] = None


@dataclass
class GitRepositoryInfo:
    root_path: Path
    git_dir: Path


# =============================================================================
# Repository discovery & validation
# =============================================================================

def find_git_repository_root(start: Path) -> GitRepositoryInfo:
    """
    Locate the root of a git repository by walking up the directory tree.
    """
    current = start.resolve()

    while True:
        git_dir = current / ".git"
        if git_dir.exists() and git_dir.is_dir():
            logger.info("Found git repository at %s", current)
            return GitRepositoryInfo(
                root_path=current,
                git_dir=git_dir,
            )

        if current.parent == current:
            break

        current = current.parent

    raise GitRepositoryNotFoundError(
        f"No git repository found starting from {start}"
    )


def validate_git_repository(repo: GitRepositoryInfo) -> None:
    """
    Validate that a discovered repository appears usable.
    """
    if not repo.git_dir.exists():
        raise GitRepositoryNotFoundError(
            f"Missing .git directory at {repo.git_dir}"
        )

    if not (repo.git_dir / "HEAD").exists():
        raise GitHistoryError("Invalid git repository: missing HEAD")


# =============================================================================
# Git command execution helpers
# =============================================================================

def run_git_command(
    repo: GitRepositoryInfo,
    args: List[str],
    *,
    timeout: Optional[int] = 10,
) -> str:
    """
    Execute a git command safely and return stdout.
    """
    cmd = ["git"] + args

    try:
        result = subprocess.run(
            cmd,
            cwd=str(repo.root_path),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            text=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitCommandError(f"Git command timed out: {cmd}") from exc

    if result.returncode != 0:
        raise GitCommandError(
            f"Git command failed ({result.returncode}): {result.stderr}"
        )

    return result.stdout.strip()


def is_git_available() -> bool:
    """
    Check whether git is available on the system.
    """
    try:
        subprocess.run(
            ["git", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except Exception:
        return False


# =============================================================================
# Commit log parsing
# =============================================================================

GIT_LOG_FORMAT = "%H|%an|%ae|%at|%s"


def parse_git_log_line(line: str) -> Optional[CommitRecord]:
    """
    Parse a single line of formatted git log output.
    """
    parts = line.split("|", maxsplit=4)
    if len(parts) != 5:
        return None

    commit_hash, name, email, timestamp, message = parts

    try:
        authored_date = datetime.fromtimestamp(int(timestamp))
    except ValueError:
        return None

    author = CommitAuthor(name=name, email=email)

    return CommitRecord(
        commit_hash=commit_hash,
        author=author,
        authored_date=authored_date,
        message=message,
    )


def get_commit_log(
    repo: GitRepositoryInfo,
    *,
    max_commits: Optional[int] = None,
) -> List[CommitRecord]:
    """
    Retrieve commit log records from the repository.
    """
    args = ["log", f"--pretty=format:{GIT_LOG_FORMAT}"]

    if max_commits is not None:
        args.append(f"-n{max_commits}")

    output = run_git_command(repo, args)

    commits: List[CommitRecord] = []
    for line in output.splitlines():
        record = parse_git_log_line(line)
        if record:
            commits.append(record)

    return commits


# =============================================================================
# Author normalization & grouping
# =============================================================================

def normalize_authors(commits: Iterable[CommitRecord]) -> List[CommitRecord]:
    """
    Normalize author information across commit records.
    """
    normalized: List[CommitRecord] = []

    for commit in commits:
        normalized.append(
            CommitRecord(
                commit_hash=commit.commit_hash,
                author=commit.author.normalized(),
                authored_date=commit.authored_date,
                message=commit.message,
                stats=commit.stats,
            )
        )

    return normalized


def group_commits_by_author(
    commits: Iterable[CommitRecord],
) -> Dict[str, List[CommitRecord]]:
    """
    Group commits by normalized author email.
    """
    groups: Dict[str, List[CommitRecord]] = {}

    for commit in commits:
        key = commit.author.email
        groups.setdefault(key, []).append(commit)

    return groups

# =============================================================================
# Commit statistics extraction
# =============================================================================

def parse_numstat_line(line: str) -> Optional[Tuple[int, int, str]]:
    """
    Parse a single line of git numstat output.

    Expected format:
        <insertions>\t<deletions>\t<path>

    Binary files may report '-' instead of numbers.
    """
    parts = line.split("\t")
    if len(parts) != 3:
        return None

    ins_raw, del_raw, path = parts

    try:
        insertions = int(ins_raw)
    except ValueError:
        insertions = 0

    try:
        deletions = int(del_raw)
    except ValueError:
        deletions = 0

    return insertions, deletions, path


def get_commit_stats(
    repo: GitRepositoryInfo,
    commit_hash: str,
) -> CommitStats:
    """
    Retrieve file change statistics for a specific commit.
    """
    output = run_git_command(
        repo,
        ["show", "--numstat", "--format=", commit_hash],
    )

    files_changed = 0
    insertions = 0
    deletions = 0

    for line in output.splitlines():
        parsed = parse_numstat_line(line)
        if not parsed:
            continue

        ins, dels, _path = parsed
        files_changed += 1
        insertions += ins
        deletions += dels

    return CommitStats(
        files_changed=files_changed,
        insertions=insertions,
        deletions=deletions,
    )


def attach_commit_stats(
    repo: GitRepositoryInfo,
    commits: Iterable[CommitRecord],
) -> List[CommitRecord]:
    """
    Attach CommitStats to each CommitRecord.
    """
    enriched: List[CommitRecord] = []

    for commit in commits:
        try:
            stats = get_commit_stats(repo, commit.commit_hash)
        except GitCommandError as exc:
            logger.warning(
                "Failed to retrieve stats for commit %s: %s",
                commit.commit_hash,
                exc,
            )
            stats = None

        enriched.append(
            CommitRecord(
                commit_hash=commit.commit_hash,
                author=commit.author,
                authored_date=commit.authored_date,
                message=commit.message,
                stats=stats,
            )
        )

    return enriched


# =============================================================================
# Timeline bucketing & frequency analysis
# =============================================================================

def bucket_commits_by_day(
    commits: Iterable[CommitRecord],
) -> Dict[str, List[CommitRecord]]:
    """
    Bucket commits by day (YYYY-MM-DD).
    """
    buckets: Dict[str, List[CommitRecord]] = {}

    for commit in commits:
        day = commit.authored_date.strftime("%Y-%m-%d")
        buckets.setdefault(day, []).append(commit)

    return buckets


def bucket_commits_by_month(
    commits: Iterable[CommitRecord],
) -> Dict[str, List[CommitRecord]]:
    """
    Bucket commits by month (YYYY-MM).
    """
    buckets: Dict[str, List[CommitRecord]] = {}

    for commit in commits:
        month = commit.authored_date.strftime("%Y-%m")
        buckets.setdefault(month, []).append(commit)

    return buckets


def compute_commit_frequency(
    commits: Iterable[CommitRecord],
) -> Dict[str, Any]:
    """
    Compute basic commit frequency metrics.
    """
    commits_list = list(commits)
    if not commits_list:
        return {
            "total_commits": 0,
            "days_active": 0,
            "commits_per_day": 0.0,
        }

    commits_sorted = sorted(
        commits_list,
        key=lambda c: c.authored_date,
    )

    first = commits_sorted[0].authored_date
    last = commits_sorted[-1].authored_date
    days_active = max((last - first).days + 1, 1)

    total_commits = len(commits_sorted)
    commits_per_day = round(total_commits / days_active, 3)

    return {
        "total_commits": total_commits,
        "days_active": days_active,
        "commits_per_day": commits_per_day,
    }


# =============================================================================
# File change aggregation
# =============================================================================

def aggregate_file_changes(
    commits: Iterable[CommitRecord],
) -> Dict[str, Dict[str, int]]:
    """
    Aggregate file change statistics across commits.

    Returns:
        {
            "summary": {...},
            "files": {...}
        }
    """
    summary = {
        "files_changed": 0,
        "total_insertions": 0,
        "total_deletions": 0,
    }

    per_file: Dict[str, Dict[str, int]] = {}

    for commit in commits:
        if not commit.stats:
            continue

        summary["files_changed"] += commit.stats.files_changed
        summary["total_insertions"] += commit.stats.insertions
        summary["total_deletions"] += commit.stats.deletions

    return {
        "summary": summary,
        "files": per_file,
    }


# =============================================================================
# High-level analysis helpers
# =============================================================================

def analyze_commit_activity(
    repo: GitRepositoryInfo,
    *,
    max_commits: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Perform a high-level analysis of commit activity.
    """
    commits = get_commit_log(repo, max_commits=max_commits)
    commits = normalize_authors(commits)
    commits = attach_commit_stats(repo, commits)

    by_author = group_commits_by_author(commits)
    by_day = bucket_commits_by_day(commits)
    by_month = bucket_commits_by_month(commits)
    frequency = compute_commit_frequency(commits)
    changes = aggregate_file_changes(commits)

    return {
        "authors": {
            author: len(records)
            for author, records in by_author.items()
        },
        "timeline": {
            "by_day": {k: len(v) for k, v in by_day.items()},
            "by_month": {k: len(v) for k, v in by_month.items()},
        },
        "frequency": frequency,
        "changes": changes,
    }

# =============================================================================
# Author dominance & bus factor heuristics
# =============================================================================

def compute_author_contributions(
    commits: Iterable[CommitRecord],
) -> Dict[str, Dict[str, int]]:
    """
    Compute contribution counts per author.

    Returns:
        {
            "<author_email>": {
                "commits": int,
                "insertions": int,
                "deletions": int,
            }
        }
    """
    contributions: Dict[str, Dict[str, int]] = {}

    for commit in commits:
        email = commit.author.email
        entry = contributions.setdefault(
            email,
            {"commits": 0, "insertions": 0, "deletions": 0},
        )

        entry["commits"] += 1
        if commit.stats:
            entry["insertions"] += commit.stats.insertions
            entry["deletions"] += commit.stats.deletions

    return contributions


def compute_bus_factor(
    contributions: Dict[str, Dict[str, int]],
    *,
    threshold: float = 0.5,
) -> Dict[str, Any]:
    """
    Estimate a simple bus factor based on commit dominance.

    threshold:
        Fraction of commits attributed to top contributors required
        to reach the bus factor.
    """
    total_commits = sum(v["commits"] for v in contributions.values())
    if total_commits == 0:
        return {
            "bus_factor": 0,
            "dominant_authors": [],
        }

    sorted_authors = sorted(
        contributions.items(),
        key=lambda item: item[1]["commits"],
        reverse=True,
    )

    cumulative = 0
    dominant: List[str] = []

    for email, stats in sorted_authors:
        cumulative += stats["commits"]
        dominant.append(email)
        if cumulative / total_commits >= threshold:
            break

    return {
        "bus_factor": len(dominant),
        "dominant_authors": dominant,
    }


# =============================================================================
# Inactivity & maintenance signals
# =============================================================================

def detect_inactivity(
    commits: Iterable[CommitRecord],
    *,
    inactive_days_threshold: int = 90,
) -> Dict[str, Any]:
    """
    Detect repository inactivity based on last commit date.
    """
    commits_list = list(commits)
    if not commits_list:
        return {
            "inactive": True,
            "days_since_last_commit": None,
        }

    last_commit = max(commits_list, key=lambda c: c.authored_date)
    days_since = (datetime.utcnow() - last_commit.authored_date).days

    return {
        "inactive": days_since >= inactive_days_threshold,
        "days_since_last_commit": days_since,
    }


# =============================================================================
# Commit message quality checks
# =============================================================================

MIN_COMMIT_MESSAGE_LENGTH = 10


def is_meaningful_commit_message(message: str) -> bool:
    """
    Determine whether a commit message is likely meaningful.
    """
    if not message:
        return False

    message = message.strip()
    if len(message) < MIN_COMMIT_MESSAGE_LENGTH:
        return False

    # avoid obvious low-quality messages
    lowered = message.lower()
    low_quality_markers = [
        "fix",
        "update",
        "changes",
        "stuff",
        "wip",
    ]

    return not any(lowered == marker for marker in low_quality_markers)


def analyze_commit_messages(
    commits: Iterable[CommitRecord],
) -> Dict[str, Any]:
    """
    Analyze commit message quality.
    """
    total = 0
    meaningful = 0

    for commit in commits:
        total += 1
        if is_meaningful_commit_message(commit.message):
            meaningful += 1

    ratio = round(meaningful / total, 3) if total else 0.0

    return {
        "total_messages": total,
        "meaningful_messages": meaningful,
        "meaningful_ratio": ratio,
    }


# =============================================================================
# Scoring heuristics
# =============================================================================

def compute_history_score(
    frequency: Dict[str, Any],
    inactivity: Dict[str, Any],
    bus_factor: Dict[str, Any],
    message_quality: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compute a heuristic score representing repository history health.
    """
    score = 100.0

    if inactivity.get("inactive"):
        score -= 30.0

    commits_per_day = frequency.get("commits_per_day", 0.0)
    if commits_per_day < 0.01:
        score -= 20.0
    elif commits_per_day < 0.05:
        score -= 10.0

    if bus_factor.get("bus_factor", 0) <= 1:
        score -= 15.0

    meaningful_ratio = message_quality.get("meaningful_ratio", 0.0)
    if meaningful_ratio < 0.3:
        score -= 10.0

    return {
        "score": max(round(score, 2), 0.0),
        "components": {
            "frequency": frequency,
            "inactivity": inactivity,
            "bus_factor": bus_factor,
            "message_quality": message_quality,
        },
    }


# =============================================================================
# Report builders
# =============================================================================

def build_git_history_report(
    repo: GitRepositoryInfo,
    *,
    max_commits: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build a comprehensive git history report.
    """
    commits = get_commit_log(repo, max_commits=max_commits)
    commits = normalize_authors(commits)
    commits = attach_commit_stats(repo, commits)

    frequency = compute_commit_frequency(commits)
    inactivity = detect_inactivity(commits)
    contributions = compute_author_contributions(commits)
    bus_factor = compute_bus_factor(contributions)
    message_quality = analyze_commit_messages(commits)
    history_score = compute_history_score(
        frequency,
        inactivity,
        bus_factor,
        message_quality,
    )

    return {
        "summary": {
            "total_commits": frequency["total_commits"],
            "days_active": frequency["days_active"],
            "commits_per_day": frequency["commits_per_day"],
        },
        "authors": contributions,
        "bus_factor": bus_factor,
        "inactivity": inactivity,
        "commit_message_quality": message_quality,
        "score": history_score,
    }


# =============================================================================
# Orchestration entry point
# =============================================================================

def analyze_git_history(
    path: Path,
    *,
    max_commits: Optional[int] = None,
) -> Dict[str, Any]:
    """
    High-level entry point for git history analysis.

    This function performs:
    - repository discovery
    - validation
    - history analysis
    - report construction
    """
    if not is_git_available():
        raise GitHistoryError("git is not available on this system")

    repo = find_git_repository_root(path)
    validate_git_repository(repo)

    report = build_git_history_report(
        repo,
        max_commits=max_commits,
    )

    return report


# =============================================================================
# End of module
# =============================================================================
