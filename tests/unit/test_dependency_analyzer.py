from pathlib import Path
import json

import pytest

from src.analyzers.dependency_analyzers import (
    DependencyType,
    DependencySource,
    LicenseType,
    DependencyInfo,
    DependencyAnalysis,
    discover_dependency_files,
    parse_requirements_txt,
    parse_package_json,
    parse_dependency_file,
    merge_dependencies,
    deduplicate_dependencies,
    is_version_outdated,
    mark_outdated_dependencies,
    attach_licenses,
    attach_vulnerabilities,
    compute_health_score,
    generate_recommendations,
    analyze_dependency_files,
    summarize_dependencies,
    analyze_repository_dependencies,
    compute_ecosystem_confidence,
    compute_confidence_summary,
    analyze_dependency_conflicts,
    generate_dependency_findings,
    build_explainability_report,
    classify_dependency_usage,
    estimate_upgrade_impact,
    build_dependency_insights,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """
    Create a fake repository with dependency files.
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    (repo / "requirements.txt").write_text(
        "requests==2.31.0\nflask==0.12.0\n",
        encoding="utf-8",
    )

    (repo / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"react": "^18.0.0"},
                "devDependencies": {"jest": "^29.0.0"},
            }
        ),
        encoding="utf-8",
    )

    return repo


# =============================================================================
# Discovery & parsing
# =============================================================================

def test_discover_dependency_files(repo: Path):
    discovered = discover_dependency_files(repo)
    assert len(discovered) >= 2
    assert any(p.name == "requirements.txt" for p in discovered)


def test_parse_requirements_txt(repo: Path):
    deps = parse_requirements_txt(repo / "requirements.txt")
    assert "requests" in deps
    assert deps["flask"].version.startswith("0.")


def test_parse_package_json(repo: Path):
    deps = parse_package_json(repo / "package.json")
    assert "react" in deps
    assert deps["jest"].dependency_type == DependencyType.DEVELOPMENT


def test_parse_dependency_file_dispatch(repo: Path):
    path = repo / "requirements.txt"
    deps = parse_dependency_file(path, DependencySource.PYTHON)
    assert deps


# =============================================================================
# Merging & deduplication
# =============================================================================

def test_merge_and_deduplicate():
    a = DependencyInfo("A", "1.0", DependencySource.PYTHON)
    b = DependencyInfo("a", "2.0", DependencySource.PYTHON)

    merged = merge_dependencies({"A": a}, {"a": b})
    deduped = deduplicate_dependencies(merged)

    assert len(deduped) == 1
    assert list(deduped.values())[0].version in {"1.0", "2.0"}


# =============================================================================
# Outdated & vulnerability detection
# =============================================================================

def test_is_version_outdated():
    assert is_version_outdated("0.9.0") is True
    assert is_version_outdated("1.2.3") is False


def test_mark_outdated_dependencies():
    deps = {
        "x": DependencyInfo("x", "0.1.0", DependencySource.PYTHON),
        "y": DependencyInfo("y", "1.0.0", DependencySource.PYTHON),
    }
    count = mark_outdated_dependencies(deps)
    assert count == 1


def test_attach_licenses_and_vulns():
    deps = {
        "react": DependencyInfo("react", "18.0.0", DependencySource.JAVASCRIPT),
        "flask": DependencyInfo("flask", "0.12.0", DependencySource.PYTHON),
    }

    attach_licenses(deps)
    vuln_count = attach_vulnerabilities(deps)

    assert deps["react"].license == LicenseType.MIT
    assert vuln_count >= 1


# =============================================================================
# Health score & recommendations
# =============================================================================

def test_compute_health_score():
    score = compute_health_score(total=10, vulnerable=2, outdated=1)
    assert 0.0 <= score <= 1.0


def test_generate_recommendations():
    analysis = DependencyAnalysis(
        total_dependencies=5,
        vulnerable_dependencies=2,
        outdated_dependencies=1,
        health_score=0.5,
    )
    recs = generate_recommendations(analysis)
    assert recs


# =============================================================================
# Repository-level analysis
# =============================================================================

def test_analyze_dependency_files(repo: Path):
    analysis = analyze_dependency_files(repo)
    assert analysis.total_dependencies > 0
    assert analysis.health_score <= 1.0


def test_summarize_dependencies(repo: Path):
    analysis = analyze_dependency_files(repo)
    summary = summarize_dependencies(analysis)
    assert "total" in summary
    assert summary["total"] == analysis.total_dependencies


def test_public_api(repo: Path):
    report = analyze_repository_dependencies(repo)
    assert "dependencies" in report
    assert "recommendations" in report


# =============================================================================
# Ecosystem confidence
# =============================================================================

def test_compute_ecosystem_confidence():
    dep = DependencyInfo(
        name="test",
        version="0.1.0",
        source=DependencySource.PYTHON,
        license=LicenseType.UNKNOWN,
    )

    conf = compute_ecosystem_confidence(dep)
    assert conf.confidence_score < 1.0
    assert conf.reasons


def test_compute_confidence_summary(repo: Path):
    analysis = analyze_dependency_files(repo)
    summary = compute_confidence_summary(analysis.dependencies)
    assert "average_confidence" in summary


# =============================================================================
# Conflict detection
# =============================================================================

def test_analyze_dependency_conflicts():
    deps = {
        "lib": DependencyInfo("lib", "1.0", DependencySource.PYTHON),
        "Lib": DependencyInfo("Lib", "2.0", DependencySource.JAVASCRIPT),
    }

    conflicts = analyze_dependency_conflicts(deps)
    assert conflicts["total_conflicts"] >= 1


# =============================================================================
# Findings & explainability
# =============================================================================

def test_generate_dependency_findings():
    dep = DependencyInfo(
        "demo",
        "0.1.0",
        DependencySource.PYTHON,
        license=LicenseType.GPL,
    )
    findings = generate_dependency_findings(dep)
    assert findings


def test_build_explainability_report(repo: Path):
    analysis = analyze_dependency_files(repo)
    report = build_explainability_report(analysis)
    assert "findings" in report
    assert "explanations" in report


# =============================================================================
# Usage & upgrade impact
# =============================================================================

def test_classify_dependency_usage():
    dep = DependencyInfo(
        "tool",
        "1.0.0",
        DependencySource.PYTHON,
        dependency_type=DependencyType.DEVELOPMENT,
    )
    profile = classify_dependency_usage(dep)
    assert profile.usage_type == "tooling"


def test_estimate_upgrade_impact():
    dep = DependencyInfo(
        "core",
        "0.5.0",
        DependencySource.PYTHON,
    )
    impact = estimate_upgrade_impact(dep)
    assert impact.risk_level in {"high", "medium", "low"}


def test_build_dependency_insights(repo: Path):
    analysis = analyze_dependency_files(repo)
    insights = build_dependency_insights(analysis)
    assert "license_distribution" in insights
    assert "usage_profiles" in insights

# =============================================================================
# Additional parsing edge cases
# =============================================================================

def test_requirements_with_comments_and_blank_lines(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    req = repo / "requirements.txt"
    req.write_text(
        """
        # core dependencies
        requests==2.31.0

        # web framework
        flask>=1.0
        """,
        encoding="utf-8",
    )

    deps = parse_requirements_txt(req)
    assert "requests" in deps
    assert "flask" in deps
    assert deps["flask"].version is not None


def test_package_json_optional_and_peer(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    pkg = repo / "package.json"
    pkg.write_text(
        json.dumps(
            {
                "dependencies": {"react": "^18.0.0"},
                "peerDependencies": {"react-dom": "^18.0.0"},
                "optionalDependencies": {"fsevents": "^2.3.2"},
            }
        ),
        encoding="utf-8",
    )

    deps = parse_package_json(pkg)
    assert deps["react"].dependency_type == DependencyType.RUNTIME
    assert deps["react-dom"].dependency_type == DependencyType.PEER
    assert deps["fsevents"].dependency_type == DependencyType.OPTIONAL


# =============================================================================
# Deduplication robustness
# =============================================================================

def test_deduplicate_case_insensitive_names():
    deps = {
        "NumPy": DependencyInfo("NumPy", "1.24.0", DependencySource.PYTHON),
        "numpy": DependencyInfo("numpy", "1.25.0", DependencySource.PYTHON),
    }

    deduped = deduplicate_dependencies(deps)
    assert len(deduped) == 1


def test_merge_preserves_vulnerabilities():
    a = DependencyInfo(
        "lib",
        "0.1.0",
        DependencySource.PYTHON,
    )
    b = DependencyInfo(
        "lib",
        "0.1.0",
        DependencySource.PYTHON,
    )

    attach_vulnerabilities({"lib": a})
    merged = merge_dependencies({"lib": a}, {"lib": b})

    assert merged["lib"].vulnerabilities


# =============================================================================
# Conflict detection depth
# =============================================================================

def test_detect_version_conflict_multiple_versions():
    deps = {
        "pkg": DependencyInfo("pkg", "1.0.0", DependencySource.PYTHON),
        "pkg_alt": DependencyInfo("pkg", "2.0.0", DependencySource.PYTHON),
    }

    conflicts = analyze_dependency_conflicts(deps)
    assert conflicts["version_conflicts"]


def test_detect_ecosystem_shadowing():
    deps = {
        "shared": DependencyInfo("shared", "1.0", DependencySource.PYTHON),
        "shared_js": DependencyInfo("shared", "1.0", DependencySource.JAVASCRIPT),
    }

    conflicts = analyze_dependency_conflicts(deps)
    assert conflicts["ecosystem_shadowing"]


# =============================================================================
# Explainability robustness
# =============================================================================

def test_explain_dependency_risk_no_issues():
    dep = DependencyInfo(
        "safe",
        "1.2.3",
        DependencySource.PYTHON,
        license=LicenseType.MIT,
    )

    explanation = explain_dependency_risk(dep)
    assert "No significant risk" in explanation


def test_explain_dependency_risk_multiple_reasons():
    dep = DependencyInfo(
        "risky",
        "0.1.0-alpha",
        DependencySource.PYTHON,
        license=LicenseType.GPL,
    )

    attach_vulnerabilities({"risky": dep})
    explanation = explain_dependency_risk(dep)

    assert "Risk due to" in explanation
    assert "," in explanation


# =============================================================================
# Confidence scoring boundaries
# =============================================================================

def test_confidence_score_bounds():
    dep = DependencyInfo(
        "unknown",
        None,
        DependencySource.UNKNOWN,
        license=LicenseType.UNKNOWN,
    )

    conf = compute_ecosystem_confidence(dep)
    assert 0.0 <= conf.confidence_score <= 1.0


# =============================================================================
# Usage classification variations
# =============================================================================

def test_usage_classification_runtime():
    dep = DependencyInfo(
        "runtime_lib",
        "1.0.0",
        DependencySource.PYTHON,
        dependency_type=DependencyType.RUNTIME,
    )

    profile = classify_dependency_usage(dep)
    assert profile.usage_type == "runtime"


def test_usage_classification_optional():
    dep = DependencyInfo(
        "opt",
        "1.0.0",
        DependencySource.PYTHON,
        dependency_type=DependencyType.OPTIONAL,
    )

    profile = classify_dependency_usage(dep)
    assert profile.criticality in {"low", "medium"}


# =============================================================================
# Upgrade impact simulation coverage
# =============================================================================

def test_upgrade_impact_unpinned_version():
    dep = DependencyInfo(
        "unpinned",
        None,
        DependencySource.PYTHON,
    )

    impact = estimate_upgrade_impact(dep)
    assert impact.risk_level == "unknown"


def test_upgrade_impact_tooling_dependency():
    dep = DependencyInfo(
        "tool",
        "1.0.0",
        DependencySource.PYTHON,
        dependency_type=DependencyType.DEVELOPMENT,
    )

    impact = estimate_upgrade_impact(dep)
    assert impact.estimated_effort == "low"


# =============================================================================
# Insights aggregation depth
# =============================================================================

def test_dependency_insights_contains_all_sections(repo: Path):
    analysis = analyze_dependency_files(repo)
    insights = build_dependency_insights(analysis)

    assert "license_distribution" in insights
    assert "high_risk_dependencies" in insights
    assert "usage_profiles" in insights
    assert "upgrade_impacts" in insights

# =============================================================================
# Multi-ecosystem parsing & aggregation
# =============================================================================

def test_multi_ecosystem_repository(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()

    (repo / "requirements.txt").write_text(
        "requests==2.31.0\nnumpy==1.26.0\n",
        encoding="utf-8",
    )

    (repo / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"react": "^18.0.0"},
                "devDependencies": {"eslint": "^8.0.0"},
            }
        ),
        encoding="utf-8",
    )

    analysis = analyze_dependency_files(repo)

    assert analysis.total_dependencies >= 4
    assert DependencySource.PYTHON in analysis.sources_detected
    assert DependencySource.JAVASCRIPT in analysis.sources_detected


# =============================================================================
# Health score edge cases
# =============================================================================

def test_health_score_no_dependencies():
    score = compute_health_score(
        total=0,
        vulnerable=0,
        outdated=0,
    )
    assert score == 1.0


def test_health_score_all_vulnerable():
    score = compute_health_score(
        total=5,
        vulnerable=5,
        outdated=5,
    )
    assert score == 0.0


# =============================================================================
# Recommendation generation robustness
# =============================================================================

def test_recommendations_no_issues():
    analysis = DependencyAnalysis(
        total_dependencies=3,
        vulnerable_dependencies=0,
        outdated_dependencies=0,
        health_score=1.0,
    )
    recs = generate_recommendations(analysis)
    assert len(recs) == 1
    assert "No major dependency issues" in recs[0]


def test_recommendations_multiple_issues():
    analysis = DependencyAnalysis(
        total_dependencies=10,
        vulnerable_dependencies=3,
        outdated_dependencies=4,
        health_score=0.4,
    )
    recs = generate_recommendations(analysis)
    assert len(recs) >= 2


# =============================================================================
# Confidence summary determinism
# =============================================================================

def test_confidence_summary_deterministic(repo: Path):
    analysis = analyze_dependency_files(repo)

    s1 = compute_confidence_summary(analysis.dependencies)
    s2 = compute_confidence_summary(analysis.dependencies)

    assert s1 == s2


# =============================================================================
# Conflict analysis corner cases
# =============================================================================

def test_conflict_analysis_no_conflicts():
    deps = {
        "a": DependencyInfo("a", "1.0.0", DependencySource.PYTHON),
        "b": DependencyInfo("b", "2.0.0", DependencySource.PYTHON),
    }

    conflicts = analyze_dependency_conflicts(deps)
    assert conflicts["total_conflicts"] == 0


def test_conflict_analysis_multiple_types():
    deps = {
        "x": DependencyInfo("x", "1.0.0", DependencySource.PYTHON),
        "x_dev": DependencyInfo(
            "x",
            "1.0.0",
            DependencySource.PYTHON,
            dependency_type=DependencyType.DEVELOPMENT,
        ),
        "x_js": DependencyInfo("x", "1.0.0", DependencySource.JAVASCRIPT),
    }

    conflicts = analyze_dependency_conflicts(deps)
    assert conflicts["total_conflicts"] >= 2


# =============================================================================
# Explainability aggregation integrity
# =============================================================================

def test_explainability_summary_matches_findings(repo: Path):
    analysis = analyze_dependency_files(repo)
    report = build_explainability_report(analysis)

    summary = report["finding_summary"]
    findings = report["findings"]

    assert sum(summary.values()) == len(findings)


def test_explainability_has_all_dependencies(repo: Path):
    analysis = analyze_dependency_files(repo)
    report = build_explainability_report(analysis)

    explanations = report["explanations"]
    for name in analysis.dependencies:
        assert name in explanations


# =============================================================================
# Usage profile consistency
# =============================================================================

def test_usage_profile_reasoning_not_empty(repo: Path):
    analysis = analyze_dependency_files(repo)
    insights = build_dependency_insights(analysis)

    for profile in insights["usage_profiles"].values():
        assert profile["reasoning"]


# =============================================================================
# Upgrade impact consistency
# =============================================================================

def test_upgrade_impact_present_for_all_dependencies(repo: Path):
    analysis = analyze_dependency_files(repo)
    insights = build_dependency_insights(analysis)

    impacts = insights["upgrade_impacts"]
    for dep_name in analysis.dependencies:
        assert dep_name in impacts


def test_upgrade_impact_risk_levels_valid(repo: Path):
    analysis = analyze_dependency_files(repo)
    insights = build_dependency_insights(analysis)

    for impact in insights["upgrade_impacts"].values():
        assert impact["risk_level"] in {
            "low",
            "medium",
            "high",
            "unknown",
        }


# =============================================================================
# End-to-end stability
# =============================================================================

def test_full_dependency_analysis_is_stable(repo: Path):
    result1 = analyze_repository_dependencies(repo)
    result2 = analyze_repository_dependencies(repo)

    assert result1 == result2
