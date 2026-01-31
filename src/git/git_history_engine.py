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
