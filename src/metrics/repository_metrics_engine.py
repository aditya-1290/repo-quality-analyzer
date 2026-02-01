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

# =============================================================================
# Normalization utilities
# =============================================================================

def clamp(value: float, *, min_value: float = 0.0, max_value: float = 1.0) -> float:
    """
    Clamp a floating point value to a fixed range.
    """
    return max(min_value, min(max_value, value))


def normalize_ratio(
    numerator: float,
    denominator: float,
    *,
    default: float = 0.0,
) -> float:
    """
    Safely normalize a ratio.
    """
    if denominator <= 0:
        return default
    return clamp(numerator / denominator)


def normalize_inverse(
    value: float,
    *,
    scale: float,
) -> float:
    """
    Normalize an inverse metric where lower values are better.
    """
    if value <= 0:
        return 1.0
    return clamp(1.0 - (value / scale))


# =============================================================================
# Threshold definitions
# =============================================================================

@dataclass
class MetricThresholds:
    min_commits_per_day: float = 0.01
    max_days_inactive: int = 120
    min_bus_factor: int = 2
    min_meaningful_commit_ratio: float = 0.3
    max_average_churn: float = 500.0
    max_merge_ratio: float = 0.5


DEFAULT_THRESHOLDS = MetricThresholds()


# =============================================================================
# Scoring components
# =============================================================================

def score_activity(
    activity: ActivityMetrics,
    *,
    thresholds: MetricThresholds = DEFAULT_THRESHOLDS,
) -> Dict[str, float]:
    """
    Score repository activity signals.
    """
    score = 0.0
    components: Dict[str, float] = {}

    freq_score = normalize_ratio(
        activity.commits_per_day,
        thresholds.min_commits_per_day,
        default=0.0,
    )
    components["frequency"] = freq_score
    score += freq_score

    inactivity_penalty = 0.0
    if activity.inactive and activity.days_since_last_commit is not None:
        inactivity_penalty = normalize_inverse(
            activity.days_since_last_commit,
            scale=thresholds.max_days_inactive,
        )
    components["recency"] = inactivity_penalty
    score += inactivity_penalty

    return {
        "score": clamp(score / 2.0),
        "components": components,
    }


def score_quality(
    quality: QualitySignals,
    *,
    thresholds: MetricThresholds = DEFAULT_THRESHOLDS,
) -> Dict[str, float]:
    """
    Score repository quality signals.
    """
    score = 0.0
    components: Dict[str, float] = {}

    bus_score = normalize_ratio(
        quality.bus_factor,
        thresholds.min_bus_factor,
        default=0.0,
    )
    components["bus_factor"] = bus_score
    score += bus_score

    msg_score = clamp(quality.meaningful_commit_ratio)
    components["commit_messages"] = msg_score
    score += msg_score

    churn_score = normalize_inverse(
        quality.churn_average,
        scale=thresholds.max_average_churn,
    )
    components["churn"] = churn_score
    score += churn_score

    merge_score = normalize_inverse(
        quality.merge_ratio,
        scale=thresholds.max_merge_ratio,
    )
    components["merges"] = merge_score
    score += merge_score

    return {
        "score": clamp(score / 4.0),
        "components": components,
    }


def score_structure(
    structural: StructuralMetrics,
) -> Dict[str, float]:
    """
    Score structural characteristics of the repository.
    """
    components: Dict[str, float] = {}

    language_diversity = len(structural.languages)
    components["language_diversity"] = clamp(language_diversity / 5.0)

    test_ratio = normalize_ratio(
        structural.file_categories.get("test", 0),
        structural.files_counted,
    )
    components["test_coverage_proxy"] = test_ratio

    documentation_ratio = normalize_ratio(
        structural.file_categories.get("docs", 0),
        structural.files_counted,
    )
    components["documentation_proxy"] = documentation_ratio

    score = (
        components["language_diversity"]
        + components["test_coverage_proxy"]
        + components["documentation_proxy"]
    ) / 3.0

    return {
        "score": clamp(score),
        "components": components,
    }


# =============================================================================
# Composite scoring
# =============================================================================

def compute_composite_score(
    structural: StructuralMetrics,
    activity: ActivityMetrics,
    quality: QualitySignals,
    *,
    weights: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Compute a weighted composite repository score.
    """
    weights = weights or {
        "structure": 0.3,
        "activity": 0.3,
        "quality": 0.4,
    }

    struct_score = score_structure(structural)
    act_score = score_activity(activity)
    qual_score = score_quality(quality)

    total = (
        struct_score["score"] * weights["structure"]
        + act_score["score"] * weights["activity"]
        + qual_score["score"] * weights["quality"]
    )

    return {
        "total_score": round(clamp(total), 3),
        "breakdown": {
            "structure": struct_score,
            "activity": act_score,
            "quality": qual_score,
        },
    }


# =============================================================================
# Risk flags & comparisons
# =============================================================================

def detect_risk_flags(
    activity: ActivityMetrics,
    quality: QualitySignals,
    *,
    thresholds: MetricThresholds = DEFAULT_THRESHOLDS,
) -> List[str]:
    """
    Detect risk flags based on metric thresholds.
    """
    flags: List[str] = []

    if activity.inactive:
        flags.append("inactive_repository")

    if quality.bus_factor < thresholds.min_bus_factor:
        flags.append("low_bus_factor")

    if quality.meaningful_commit_ratio < thresholds.min_meaningful_commit_ratio:
        flags.append("poor_commit_messages")

    if quality.churn_average > thresholds.max_average_churn:
        flags.append("high_churn")

    if quality.merge_ratio > thresholds.max_merge_ratio:
        flags.append("excessive_merges")

    return flags


def compare_repositories(
    metrics_a: RepositoryMetrics,
    metrics_b: RepositoryMetrics,
) -> Dict[str, Any]:
    """
    Compare two repositories across key metrics.
    """
    comparison: Dict[str, Any] = {}

    comparison["total_score_diff"] = (
        compute_composite_score(
            metrics_a.structural,
            metrics_a.activity,
            metrics_a.quality,
        )["total_score"]
        - compute_composite_score(
            metrics_b.structural,
            metrics_b.activity,
            metrics_b.quality,
        )["total_score"]
    )

    comparison["activity"] = {
        "commits_per_day": (
            metrics_a.activity.commits_per_day
            - metrics_b.activity.commits_per_day
        )
    }

    comparison["quality"] = {
        "bus_factor": (
            metrics_a.quality.bus_factor
            - metrics_b.quality.bus_factor
        ),
        "meaningful_commit_ratio": (
            metrics_a.quality.meaningful_commit_ratio
            - metrics_b.quality.meaningful_commit_ratio
        ),
    }

    return comparison
   
