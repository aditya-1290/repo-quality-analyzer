"""
Repository Metrics Engine

Aggregates filesystem and git history signals into cohesive
repository-level metrics and quality indicators.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime

from src.utils.repository_utils import (
    count_repository_lines,
    aggregate_language_stats,
    aggregate_file_categories,
)
from src.utils.filesystem_scanner import (
    scan_repository_quick,
    scan_repository_detailed,
    ScanLimits,
)
from src.git.git_history_engine import (
    analyze_git_history,
    build_extended_git_history_report,
)

LOGGER_NAME = "repo_quality.metrics"
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(logging.INFO)


# =============================================================================
# Exceptions
# =============================================================================

class RepositoryMetricsError(Exception):
    """Base exception for repository metrics."""


# =============================================================================
# Data models
# =============================================================================

@dataclass
class StructuralMetrics:
    total_lines: int
    files_counted: int
    blank_lines: int
    non_blank_lines: int
    languages: Dict[str, int]
    file_categories: Dict[str, int]


@dataclass
class ActivityMetrics:
    total_commits: int
    commits_per_day: float
    days_active: int
    inactive: bool
    days_since_last_commit: Optional[int] = None


@dataclass
class QualitySignals:
    bus_factor: int
    meaningful_commit_ratio: float
    churn_average: float
    merge_ratio: float


@dataclass
class RepositoryMetrics:
    generated_at: datetime
    structural: StructuralMetrics
    activity: ActivityMetrics
    quality: QualitySignals
    raw: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Structural metrics
# =============================================================================

def compute_structural_metrics(repo_path: Path) -> StructuralMetrics:
    """
    Compute structural metrics from repository contents.
    """
    lines = count_repository_lines(repo_path)
    languages = aggregate_language_stats(repo_path)
    categories = aggregate_file_categories(repo_path)

    return StructuralMetrics(
        total_lines=lines["total_lines"],
        files_counted=lines["files_counted"],
        blank_lines=lines["blank_lines"],
        non_blank_lines=lines["non_blank_lines"],
        languages=languages,
        file_categories=categories,
    )


# =============================================================================
# Activity metrics
# =============================================================================

def compute_activity_metrics(
    repo_path: Path,
    *,
    max_commits: Optional[int] = None,
) -> ActivityMetrics:
    """
    Compute activity metrics from git history.
    """
    history = analyze_git_history(
        repo_path,
        max_commits=max_commits,
    )

    frequency = history["summary"]
    inactivity = history["inactivity"]

    return ActivityMetrics(
        total_commits=frequency["total_commits"],
        commits_per_day=frequency["commits_per_day"],
        days_active=frequency["days_active"],
        inactive=inactivity["inactive"],
        days_since_last_commit=inactivity.get("days_since_last_commit"),
    )


# =============================================================================
# Quality signals
# =============================================================================

def compute_quality_signals(
    repo_path: Path,
    *,
    max_commits: Optional[int] = None,
) -> QualitySignals:
    """
    Compute higher-level quality signals.
    """
    extended = build_extended_git_history_report(
        find_path := repo_path,
        max_commits=max_commits,
    )

    bus = extended["bus_factor"]["bus_factor"]
    msg_ratio = extended["commit_message_quality"]["meaningful_ratio"]
    churn_avg = extended["churn"]["average_churn"]
    merge_ratio = extended["merges"]["merge_ratio"]

    return QualitySignals(
        bus_factor=bus,
        meaningful_commit_ratio=msg_ratio,
        churn_average=churn_avg,
        merge_ratio=merge_ratio,
    )


# =============================================================================
# Orchestration (partial)
# =============================================================================

def compute_repository_metrics(
    repo_path: Path,
    *,
    max_commits: Optional[int] = None,
    include_raw: bool = False,
) -> RepositoryMetrics:
    """
    Compute a unified set of repository metrics.
    """
    try:
        structural = compute_structural_metrics(repo_path)
        activity = compute_activity_metrics(
            repo_path,
            max_commits=max_commits,
        )
        quality = compute_quality_signals(
            repo_path,
            max_commits=max_commits,
        )
    except Exception as exc:
        raise RepositoryMetricsError(
            f"Failed to compute metrics: {exc}"
        ) from exc

    raw: Dict[str, Any] = {}
    if include_raw:
        raw["filesystem_quick"] = scan_repository_quick(repo_path)
        raw["filesystem_detailed"] = scan_repository_detailed(
            repo_path,
            limits=ScanLimits(max_depth=10),
        )

    return RepositoryMetrics(
        generated_at=datetime.utcnow(),
        structural=structural,
        activity=activity,
        quality=quality,
        raw=raw,
    )
