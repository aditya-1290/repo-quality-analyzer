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
   
# =============================================================================
# Presets
# =============================================================================

@dataclass
class MetricsPreset:
    name: str
    thresholds: MetricThresholds
    weights: Dict[str, float]
    description: str


STRICT_PRESET = MetricsPreset(
    name="strict",
    thresholds=MetricThresholds(
        min_commits_per_day=0.05,
        max_days_inactive=60,
        min_bus_factor=3,
        min_meaningful_commit_ratio=0.5,
        max_average_churn=300.0,
        max_merge_ratio=0.3,
    ),
    weights={"structure": 0.3, "activity": 0.35, "quality": 0.35},
    description="Strict evaluation for production-grade repositories.",
)

RELAXED_PRESET = MetricsPreset(
    name="relaxed",
    thresholds=MetricThresholds(),
    weights={"structure": 0.3, "activity": 0.3, "quality": 0.4},
    description="Relaxed evaluation for early-stage or research repositories.",
)

RESEARCH_PRESET = MetricsPreset(
    name="research",
    thresholds=MetricThresholds(
        min_commits_per_day=0.005,
        max_days_inactive=180,
        min_bus_factor=1,
        min_meaningful_commit_ratio=0.2,
        max_average_churn=800.0,
        max_merge_ratio=0.6,
    ),
    weights={"structure": 0.25, "activity": 0.25, "quality": 0.5},
    description="Research-oriented evaluation prioritizing experimentation.",
)


PRESETS = {
    STRICT_PRESET.name: STRICT_PRESET,
    RELAXED_PRESET.name: RELAXED_PRESET,
    RESEARCH_PRESET.name: RESEARCH_PRESET,
}


# =============================================================================
# Report builders
# =============================================================================

def build_metrics_report(
    metrics: RepositoryMetrics,
    *,
    preset: Optional[MetricsPreset] = None,
) -> Dict[str, Any]:
    """
    Build a structured metrics report suitable for JSON export.
    """
    preset = preset or RELAXED_PRESET

    composite = compute_composite_score(
        metrics.structural,
        metrics.activity,
        metrics.quality,
        weights=preset.weights,
    )

    risks = detect_risk_flags(
        metrics.activity,
        metrics.quality,
        thresholds=preset.thresholds,
    )

    return {
        "generated_at": metrics.generated_at.isoformat(),
        "preset": preset.name,
        "scores": composite,
        "risk_flags": risks,
        "structural": metrics.structural.__dict__,
        "activity": metrics.activity.__dict__,
        "quality": metrics.quality.__dict__,
    }


def build_compact_metrics_report(
    metrics: RepositoryMetrics,
    *,
    preset: Optional[MetricsPreset] = None,
) -> Dict[str, Any]:
    """
    Build a compact report intended for CLI output.
    """
    preset = preset or RELAXED_PRESET

    composite = compute_composite_score(
        metrics.structural,
        metrics.activity,
        metrics.quality,
        weights=preset.weights,
    )

    return {
        "score": composite["total_score"],
        "inactive": metrics.activity.inactive,
        "bus_factor": metrics.quality.bus_factor,
        "commits_per_day": metrics.activity.commits_per_day,
        "languages": len(metrics.structural.languages),
        "files": metrics.structural.files_counted,
    }


# =============================================================================
# Export helpers
# =============================================================================

def export_metrics_to_json(
    report: Dict[str, Any],
    *,
    indent: int = 2,
) -> str:
    """
    Export metrics report to JSON string.
    """
    import json

    return json.dumps(report, indent=indent, sort_keys=True)


def export_metrics_to_markdown(
    report: Dict[str, Any],
) -> str:
    """
    Export metrics report to a human-readable Markdown summary.
    """
    lines: List[str] = []

    lines.append(f"# Repository Metrics Report ({report['preset']})")
    lines.append("")
    lines.append(f"**Generated at:** {report['generated_at']}")
    lines.append("")
    lines.append(f"## Overall Score: {report['scores']['total_score']}")
    lines.append("")

    if report["risk_flags"]:
        lines.append("## ⚠ Risk Flags")
        for flag in report["risk_flags"]:
            lines.append(f"- {flag}")
        lines.append("")
    else:
        lines.append("No significant risk flags detected.\n")

    lines.append("## Activity")
    lines.append(f"- Commits per day: {report['activity']['commits_per_day']}")
    lines.append(f"- Days active: {report['activity']['days_active']}")
    lines.append("")

    lines.append("## Structure")
    lines.append(f"- Files counted: {report['structural']['files_counted']}")
    lines.append(f"- Languages: {len(report['structural']['languages'])}")
    lines.append("")

    lines.append("## Quality")
    lines.append(f"- Bus factor: {report['quality']['bus_factor']}")
    lines.append(
        f"- Meaningful commit ratio: "
        f"{report['quality']['meaningful_commit_ratio']}"
    )

    return "\n".join(lines)


# =============================================================================
# Final orchestration wrappers
# =============================================================================

def analyze_repository(
    repo_path: Path,
    *,
    preset_name: str = "relaxed",
    max_commits: Optional[int] = None,
    include_raw: bool = False,
) -> Dict[str, Any]:
    """
    High-level orchestration wrapper.

    This is the main entry point intended for CLI or API usage.
    """
    preset = PRESETS.get(preset_name)
    if not preset:
        raise RepositoryMetricsError(
            f"Unknown metrics preset: {preset_name}"
        )

    metrics = compute_repository_metrics(
        repo_path,
        max_commits=max_commits,
        include_raw=include_raw,
    )

    report = build_metrics_report(
        metrics,
        preset=preset,
    )

    return report


def analyze_repository_compact(
    repo_path: Path,
    *,
    preset_name: str = "relaxed",
    max_commits: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Compact orchestration wrapper for CLI summaries.
    """
    preset = PRESETS.get(preset_name)
    if not preset:
        raise RepositoryMetricsError(
            f"Unknown metrics preset: {preset_name}"
        )

    metrics = compute_repository_metrics(
        repo_path,
        max_commits=max_commits,
        include_raw=False,
    )

    return build_compact_metrics_report(
        metrics,
        preset=preset,
    )

# =============================================================================
# Historical trend & stability analysis
# =============================================================================

def compute_activity_trend(
    commits_per_day: float,
    *,
    low_threshold: float = 0.01,
    high_threshold: float = 0.1,
) -> str:
    """
    Classify activity trend based on commit frequency.
    """
    if commits_per_day >= high_threshold:
        return "high"
    if commits_per_day >= low_threshold:
        return "moderate"
    return "low"


def compute_churn_stability(
    churn_average: float,
    *,
    stable_threshold: float = 200.0,
    volatile_threshold: float = 600.0,
) -> str:
    """
    Classify churn stability.
    """
    if churn_average <= stable_threshold:
        return "stable"
    if churn_average <= volatile_threshold:
        return "moderate"
    return "volatile"


def compute_bus_factor_risk(
    bus_factor: int,
) -> str:
    """
    Classify bus factor risk.
    """
    if bus_factor >= 4:
        return "low"
    if bus_factor >= 2:
        return "medium"
    return "high"


# =============================================================================
# Metric deltas & normalization helpers
# =============================================================================

def compute_metric_delta(
    current: float,
    previous: Optional[float],
) -> Optional[float]:
    """
    Compute delta between current and previous metric values.
    """
    if previous is None:
        return None
    return round(current - previous, 4)


def compute_activity_delta(
    current: ActivityMetrics,
    previous: Optional[ActivityMetrics],
) -> Dict[str, Optional[float]]:
    """
    Compute deltas for activity metrics.
    """
    if previous is None:
        return {
            "commits_per_day": None,
            "days_active": None,
        }

    return {
        "commits_per_day": compute_metric_delta(
            current.commits_per_day,
            previous.commits_per_day,
        ),
        "days_active": compute_metric_delta(
            current.days_active,
            previous.days_active,
        ),
    }


def compute_quality_delta(
    current: QualitySignals,
    previous: Optional[QualitySignals],
) -> Dict[str, Optional[float]]:
    """
    Compute deltas for quality signals.
    """
    if previous is None:
        return {
            "bus_factor": None,
            "meaningful_commit_ratio": None,
            "churn_average": None,
        }

    return {
        "bus_factor": compute_metric_delta(
            current.bus_factor,
            previous.bus_factor,
        ),
        "meaningful_commit_ratio": compute_metric_delta(
            current.meaningful_commit_ratio,
            previous.meaningful_commit_ratio,
        ),
        "churn_average": compute_metric_delta(
            current.churn_average,
            previous.churn_average,
        ),
    }


# =============================================================================
# Grading & explainability
# =============================================================================

def grade_score(score: float) -> str:
    """
    Convert a numeric score into a letter grade.
    """
    if score >= 0.85:
        return "A"
    if score >= 0.7:
        return "B"
    if score >= 0.55:
        return "C"
    return "D"


def explain_score_components(
    composite: Dict[str, Any],
) -> Dict[str, str]:
    """
    Provide human-readable explanations for score components.
    """
    explanations: Dict[str, str] = {}

    for key, section in composite["breakdown"].items():
        score = section["score"]
        grade = grade_score(score)

        explanations[key] = (
            f"{key.capitalize()} score {score} "
            f"(grade {grade})"
        )

    return explanations


# =============================================================================
# Extended evaluation summary
# =============================================================================

def build_evaluation_summary(
    metrics: RepositoryMetrics,
    *,
    preset: MetricsPreset,
) -> Dict[str, Any]:
    """
    Build an extended evaluation summary with trends and grades.
    """
    composite = compute_composite_score(
        metrics.structural,
        metrics.activity,
        metrics.quality,
        weights=preset.weights,
    )

    summary = {
        "overall_score": composite["total_score"],
        "grade": grade_score(composite["total_score"]),
        "activity_trend": compute_activity_trend(
            metrics.activity.commits_per_day
        ),
        "churn_stability": compute_churn_stability(
            metrics.quality.churn_average
        ),
        "bus_factor_risk": compute_bus_factor_risk(
            metrics.quality.bus_factor
        ),
        "explanations": explain_score_components(composite),
    }

    return summary


def build_full_evaluation(
    repo_path: Path,
    *,
    preset_name: str = "relaxed",
    max_commits: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build a full evaluation including metrics, scores, and explanations.
    """
    preset = PRESETS.get(preset_name)
    if not preset:
        raise RepositoryMetricsError(
            f"Unknown metrics preset: {preset_name}"
        )

    metrics = compute_repository_metrics(
        repo_path,
        max_commits=max_commits,
        include_raw=False,
    )

    report = build_metrics_report(
        metrics,
        preset=preset,
    )

    report["evaluation"] = build_evaluation_summary(
        metrics,
        preset=preset,
    )

    return report


# =============================================================================
# End of module
# =============================================================================
