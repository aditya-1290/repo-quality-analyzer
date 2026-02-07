"""
Dependency Analyzer

Performs multi-language dependency analysis for software repositories.
Supports Python, JavaScript, Go, Rust, PHP, Ruby, and JVM-based projects.

This module is intentionally self-contained and side-effect free.
"""

from __future__ import annotations

import os
import re
import json
import tomllib
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# =============================================================================
# Enums
# =============================================================================

class DependencyType(str, Enum):
    RUNTIME = "runtime"
    DEVELOPMENT = "development"
    BUILD = "build"
    OPTIONAL = "optional"
    PEER = "peer"
    UNKNOWN = "unknown"


class DependencySource(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    RUBY = "ruby"
    JVM = "jvm"
    UNKNOWN = "unknown"


class LicenseType(str, Enum):
    MIT = "MIT"
    APACHE = "Apache-2.0"
    GPL = "GPL"
    BSD = "BSD"
    MPL = "MPL"
    PROPRIETARY = "Proprietary"
    UNKNOWN = "Unknown"


class VulnerabilitySeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class Vulnerability:
    identifier: str
    severity: VulnerabilitySeverity
    description: Optional[str] = None
    fixed_version: Optional[str] = None


@dataclass
class DependencyInfo:
    name: str
    version: Optional[str]
    source: DependencySource
    dependency_type: DependencyType = DependencyType.RUNTIME
    license: LicenseType = LicenseType.UNKNOWN
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    def is_vulnerable(self) -> bool:
        return any(
            v.severity in {VulnerabilitySeverity.HIGH, VulnerabilitySeverity.CRITICAL}
            for v in self.vulnerabilities
        )


@dataclass
class DependencyAnalysis:
    dependencies: Dict[str, DependencyInfo] = field(default_factory=dict)
    sources_detected: Set[DependencySource] = field(default_factory=set)

    total_dependencies: int = 0
    vulnerable_dependencies: int = 0
    outdated_dependencies: int = 0

    health_score: float = 1.0
    recommendations: List[str] = field(default_factory=list)


# =============================================================================
# Dependency file discovery
# =============================================================================

DEPENDENCY_FILES = {
    # Python
    "requirements.txt": DependencySource.PYTHON,
    "pyproject.toml": DependencySource.PYTHON,
    "setup.py": DependencySource.PYTHON,
    "setup.cfg": DependencySource.PYTHON,
    "Pipfile": DependencySource.PYTHON,
    "poetry.lock": DependencySource.PYTHON,

    # JavaScript
    "package.json": DependencySource.JAVASCRIPT,
    "yarn.lock": DependencySource.JAVASCRIPT,
    "pnpm-lock.yaml": DependencySource.JAVASCRIPT,

    # Go
    "go.mod": DependencySource.GO,

    # Rust
    "Cargo.toml": DependencySource.RUST,

    # PHP
    "composer.json": DependencySource.PHP,

    # Ruby
    "Gemfile": DependencySource.RUBY,

    # JVM
    "pom.xml": DependencySource.JVM,
    "build.gradle": DependencySource.JVM,
}


def discover_dependency_files(repo_path: Path) -> Dict[Path, DependencySource]:
    """
    Discover dependency-related files in a repository.
    """
    discovered: Dict[Path, DependencySource] = {}

    for root, _dirs, files in os.walk(repo_path):
        for file in files:
            if file in DEPENDENCY_FILES:
                path = Path(root) / file
                discovered[path] = DEPENDENCY_FILES[file]

    return discovered

# =============================================================================
# Version parsing & normalization
# =============================================================================

_VERSION_PATTERN = re.compile(
    r"(?P<op>>=|<=|==|~=|>|<|\^)?\s*(?P<version>[0-9a-zA-Z\.\-\+]+)"
)


def normalize_version(version: Optional[str]) -> Optional[str]:
    """
    Normalize a version string by stripping operators and whitespace.
    """
    if not version:
        return None

    match = _VERSION_PATTERN.search(version)
    if not match:
        return version.strip()

    return match.group("version").strip()


def split_name_and_version(raw: str) -> Tuple[str, Optional[str]]:
    """
    Split a dependency specification into name and version.
    """
    for sep in ["==", ">=", "<=", "~=", ">", "<", "^"]:
        if sep in raw:
            name, version = raw.split(sep, 1)
            return name.strip(), normalize_version(version)
    return raw.strip(), None


# =============================================================================
# Python dependency parsing
# =============================================================================

def parse_requirements_txt(path: Path) -> Dict[str, DependencyInfo]:
    """
    Parse requirements.txt dependencies.
    """
    deps: Dict[str, DependencyInfo] = {}

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        name, version = split_name_and_version(line)
        deps[name] = DependencyInfo(
            name=name,
            version=version,
            source=DependencySource.PYTHON,
            dependency_type=DependencyType.RUNTIME,
        )

    return deps


def parse_pyproject_toml(path: Path) -> Dict[str, DependencyInfo]:
    """
    Parse pyproject.toml dependencies.
    """
    deps: Dict[str, DependencyInfo] = {}

    data = tomllib.loads(path.read_text(encoding="utf-8"))

    project = data.get("project", {})
    for name, version in project.get("dependencies", {}).items():
        deps[name] = DependencyInfo(
            name=name,
            version=normalize_version(version),
            source=DependencySource.PYTHON,
        )

    for name, version in project.get("optional-dependencies", {}).items():
        deps[name] = DependencyInfo(
            name=name,
            version=normalize_version(version),
            source=DependencySource.PYTHON,
            dependency_type=DependencyType.OPTIONAL,
        )

    return deps


def parse_setup_cfg(path: Path) -> Dict[str, DependencyInfo]:
    """
    Parse setup.cfg dependencies.
    """
    deps: Dict[str, DependencyInfo] = {}

    content = path.read_text(encoding="utf-8")
    for line in content.splitlines():
        if "=" in line and not line.strip().startswith("["):
            name, version = line.split("=", 1)
            deps[name.strip()] = DependencyInfo(
                name=name.strip(),
                version=normalize_version(version),
                source=DependencySource.PYTHON,
            )

    return deps


# =============================================================================
# JavaScript dependency parsing
# =============================================================================

def parse_package_json(path: Path) -> Dict[str, DependencyInfo]:
    """
    Parse package.json dependencies.
    """
    deps: Dict[str, DependencyInfo] = {}

    data = json.loads(path.read_text(encoding="utf-8"))

    def _parse_section(section: str, dep_type: DependencyType):
        for name, version in data.get(section, {}).items():
            deps[name] = DependencyInfo(
                name=name,
                version=normalize_version(version),
                source=DependencySource.JAVASCRIPT,
                dependency_type=dep_type,
            )

    _parse_section("dependencies", DependencyType.RUNTIME)
    _parse_section("devDependencies", DependencyType.DEVELOPMENT)
    _parse_section("peerDependencies", DependencyType.PEER)
    _parse_section("optionalDependencies", DependencyType.OPTIONAL)

    return deps


# =============================================================================
# Go, Rust, PHP dependency parsing
# =============================================================================

def parse_go_mod(path: Path) -> Dict[str, DependencyInfo]:
    """
    Parse go.mod dependencies.
    """
    deps: Dict[str, DependencyInfo] = {}

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("require"):
            parts = line.replace("require", "").strip().split()
            if len(parts) >= 2:
                name, version = parts[0], parts[1]
                deps[name] = DependencyInfo(
                    name=name,
                    version=normalize_version(version),
                    source=DependencySource.GO,
                )

    return deps


def parse_cargo_toml(path: Path) -> Dict[str, DependencyInfo]:
    """
    Parse Cargo.toml dependencies.
    """
    deps: Dict[str, DependencyInfo] = {}

    data = tomllib.loads(path.read_text(encoding="utf-8"))
    for name, meta in data.get("dependencies", {}).items():
        version = meta if isinstance(meta, str) else meta.get("version")
        deps[name] = DependencyInfo(
            name=name,
            version=normalize_version(version),
            source=DependencySource.RUST,
        )

    return deps


def parse_composer_json(path: Path) -> Dict[str, DependencyInfo]:
    """
    Parse composer.json dependencies.
    """
    deps: Dict[str, DependencyInfo] = {}

    data = json.loads(path.read_text(encoding="utf-8"))
    for name, version in data.get("require", {}).items():
        deps[name] = DependencyInfo(
            name=name,
            version=normalize_version(version),
            source=DependencySource.PHP,
        )

    return deps


# =============================================================================
# Unified parser dispatch
# =============================================================================

def parse_dependency_file(
    path: Path,
    source: DependencySource,
) -> Dict[str, DependencyInfo]:
    """
    Dispatch dependency parsing based on file type.
    """
    filename = path.name

    if filename == "requirements.txt":
        return parse_requirements_txt(path)
    if filename == "pyproject.toml":
        return parse_pyproject_toml(path)
    if filename == "setup.cfg":
        return parse_setup_cfg(path)
    if filename == "package.json":
        return parse_package_json(path)
    if filename == "go.mod":
        return parse_go_mod(path)
    if filename == "Cargo.toml":
        return parse_cargo_toml(path)
    if filename == "composer.json":
        return parse_composer_json(path)

    return {}

# =============================================================================
# Dependency merging & deduplication
# =============================================================================

def merge_dependencies(
    existing: Dict[str, DependencyInfo],
    incoming: Dict[str, DependencyInfo],
) -> Dict[str, DependencyInfo]:
    """
    Merge two dependency maps, preferring richer metadata.
    """
    merged = dict(existing)

    for name, dep in incoming.items():
        if name not in merged:
            merged[name] = dep
            continue

        current = merged[name]

        # Prefer version if missing
        if not current.version and dep.version:
            current.version = dep.version

        # Prefer non-unknown dependency type
        if current.dependency_type == DependencyType.UNKNOWN:
            current.dependency_type = dep.dependency_type

        # Merge vulnerabilities
        current.vulnerabilities.extend(dep.vulnerabilities)

    return merged


def deduplicate_dependencies(
    deps: Dict[str, DependencyInfo],
) -> Dict[str, DependencyInfo]:
    """
    Deduplicate dependencies by normalized name.
    """
    normalized: Dict[str, DependencyInfo] = {}

    for name, dep in deps.items():
        key = name.lower()
        if key not in normalized:
            normalized[key] = dep
        else:
            normalized[key] = merge_dependencies(
                {key: normalized[key]},
                {key: dep},
            )[key]

    return normalized


# =============================================================================
# Outdated dependency detection (safe heuristic)
# =============================================================================

def is_version_outdated(
    version: Optional[str],
) -> bool:
    """
    Heuristic outdated detection.

    This avoids network calls and serves as a placeholder
    for future registry integrations.
    """
    if not version:
        return False

    parts = re.findall(r"\d+", version)
    if not parts:
        return False

    try:
        major = int(parts[0])
        return major == 0
    except ValueError:
        return False


def mark_outdated_dependencies(
    deps: Dict[str, DependencyInfo],
) -> int:
    """
    Mark outdated dependencies and return count.
    """
    count = 0
    for dep in deps.values():
        if is_version_outdated(dep.version):
            count += 1
    return count


# =============================================================================
# License analysis hooks
# =============================================================================

def resolve_license(
    dep_name: str,
) -> LicenseType:
    """
    Resolve dependency license.

    Placeholder for SPDX / registry integration.
    """
    name = dep_name.lower()

    if name.startswith("django") or name.startswith("flask"):
        return LicenseType.BSD
    if name.startswith("numpy") or name.startswith("pandas"):
        return LicenseType.BSD
    if name.startswith("react") or name.startswith("vue"):
        return LicenseType.MIT

    return LicenseType.UNKNOWN


def attach_licenses(
    deps: Dict[str, DependencyInfo],
) -> None:
    """
    Attach license metadata to dependencies.
    """
    for dep in deps.values():
        dep.license = resolve_license(dep.name)


# =============================================================================
# Vulnerability analysis hooks
# =============================================================================

def resolve_vulnerabilities(
    dep_name: str,
    version: Optional[str],
) -> List[Vulnerability]:
    """
    Placeholder vulnerability resolver.

    Safe, deterministic, and offline.
    """
    vulns: List[Vulnerability] = []

    if not version:
        return vulns

    if "alpha" in version or "beta" in version:
        vulns.append(
            Vulnerability(
                identifier=f"PRE-{dep_name.upper()}-001",
                severity=VulnerabilitySeverity.MEDIUM,
                description="Pre-release version detected",
            )
        )

    if version.startswith("0."):
        vulns.append(
            Vulnerability(
                identifier=f"ZERO-{dep_name.upper()}-001",
                severity=VulnerabilitySeverity.HIGH,
                description="Major version zero dependency",
            )
        )

    return vulns


def attach_vulnerabilities(
    deps: Dict[str, DependencyInfo],
) -> int:
    """
    Attach vulnerabilities and return vulnerable count.
    """
    count = 0
    for dep in deps.values():
        dep.vulnerabilities = resolve_vulnerabilities(dep.name, dep.version)
        if dep.is_vulnerable():
            count += 1
    return count


# =============================================================================
# Health scoring & recommendations
# =============================================================================

def compute_health_score(
    total: int,
    vulnerable: int,
    outdated: int,
) -> float:
    """
    Compute a dependency health score between 0 and 1.
    """
    if total == 0:
        return 1.0

    penalty = (
        (vulnerable / total) * 0.6
        + (outdated / total) * 0.4
    )

    return max(0.0, round(1.0 - penalty, 3))


def generate_recommendations(
    analysis: DependencyAnalysis,
) -> List[str]:
    """
    Generate human-readable recommendations.
    """
    recs: List[str] = []

    if analysis.vulnerable_dependencies > 0:
        recs.append(
            f"{analysis.vulnerable_dependencies} vulnerable dependencies detected"
        )

    if analysis.outdated_dependencies > 0:
        recs.append(
            f"{analysis.outdated_dependencies} outdated dependencies detected"
        )

    if analysis.health_score < 0.7:
        recs.append("Dependency health score is below recommended threshold")

    if not recs:
        recs.append("No major dependency issues detected")

    return recs

# =============================================================================
# Repository-level orchestration
# =============================================================================

def analyze_dependency_files(
    repo_path: Path,
) -> DependencyAnalysis:
    """
    Analyze all dependency files in a repository and aggregate results.
    """
    analysis = DependencyAnalysis()

    discovered = discover_dependency_files(repo_path)
    all_dependencies: Dict[str, DependencyInfo] = {}

    for path, source in discovered.items():
        try:
            parsed = parse_dependency_file(path, source)
        except Exception:
            # Parsing errors should not fail the whole analysis
            continue

        analysis.sources_detected.add(source)
        all_dependencies = merge_dependencies(all_dependencies, parsed)

    all_dependencies = deduplicate_dependencies(all_dependencies)

    analysis.dependencies = all_dependencies
    analysis.total_dependencies = len(all_dependencies)

    # Attach license and vulnerability information
    attach_licenses(all_dependencies)
    analysis.vulnerable_dependencies = attach_vulnerabilities(all_dependencies)

    # Outdated detection
    analysis.outdated_dependencies = mark_outdated_dependencies(all_dependencies)

    # Health scoring & recommendations
    analysis.health_score = compute_health_score(
        total=analysis.total_dependencies,
        vulnerable=analysis.vulnerable_dependencies,
        outdated=analysis.outdated_dependencies,
    )

    analysis.recommendations = generate_recommendations(analysis)

    return analysis


# =============================================================================
# Reporting helpers
# =============================================================================

def summarize_dependencies(
    analysis: DependencyAnalysis,
) -> Dict[str, int]:
    """
    Produce a compact summary of dependency analysis.
    """
    return {
        "total": analysis.total_dependencies,
        "vulnerable": analysis.vulnerable_dependencies,
        "outdated": analysis.outdated_dependencies,
        "sources": len(analysis.sources_detected),
    }


def categorize_dependencies(
    analysis: DependencyAnalysis,
) -> Dict[DependencyType, List[DependencyInfo]]:
    """
    Categorize dependencies by dependency type.
    """
    categories: Dict[DependencyType, List[DependencyInfo]] = {
        DependencyType.RUNTIME: [],
        DependencyType.DEVELOPMENT: [],
        DependencyType.BUILD: [],
        DependencyType.OPTIONAL: [],
        DependencyType.PEER: [],
        DependencyType.UNKNOWN: [],
    }

    for dep in analysis.dependencies.values():
        categories.setdefault(dep.dependency_type, []).append(dep)

    return categories


def group_dependencies_by_source(
    analysis: DependencyAnalysis,
) -> Dict[DependencySource, List[DependencyInfo]]:
    """
    Group dependencies by detected source ecosystem.
    """
    grouped: Dict[DependencySource, List[DependencyInfo]] = {}

    for dep in analysis.dependencies.values():
        grouped.setdefault(dep.source, []).append(dep)

    return grouped


# =============================================================================
# Public API
# =============================================================================

def analyze_repository_dependencies(
    repo_path: Path,
) -> Dict[str, object]:
    """
    Public API for dependency analysis.

    Returns a JSON-serializable dictionary.
    """
    analysis = analyze_dependency_files(repo_path)

    return {
        "summary": summarize_dependencies(analysis),
        "health_score": analysis.health_score,
        "sources_detected": [s.value for s in analysis.sources_detected],
        "dependencies": {
            name: {
                "version": dep.version,
                "source": dep.source.value,
                "type": dep.dependency_type.value,
                "license": dep.license.value,
                "vulnerable": dep.is_vulnerable(),
                "vulnerabilities": [
                    {
                        "id": v.identifier,
                        "severity": v.severity.value,
                        "description": v.description,
                        "fixed_version": v.fixed_version,
                    }
                    for v in dep.vulnerabilities
                ],
            }
            for name, dep in analysis.dependencies.items()
        },
        "recommendations": analysis.recommendations,
    }

# =============================================================================
# Dependency graph construction
# =============================================================================

@dataclass
class DependencyNode:
    name: str
    info: DependencyInfo
    dependencies: Set[str] = field(default_factory=set)
    dependents: Set[str] = field(default_factory=set)
    risk_score: float = 0.0


@dataclass
class DependencyGraph:
    nodes: Dict[str, DependencyNode] = field(default_factory=dict)

    def add_node(self, dep: DependencyInfo) -> None:
        if dep.name not in self.nodes:
            self.nodes[dep.name] = DependencyNode(
                name=dep.name,
                info=dep,
            )

    def add_edge(self, parent: str, child: str) -> None:
        if parent not in self.nodes or child not in self.nodes:
            return
        self.nodes[parent].dependencies.add(child)
        self.nodes[child].dependents.add(parent)

    def get_leaf_dependencies(self) -> List[DependencyNode]:
        return [
            node for node in self.nodes.values()
            if not node.dependencies
        ]

    def get_root_dependencies(self) -> List[DependencyNode]:
        return [
            node for node in self.nodes.values()
            if not node.dependents
        ]


def build_dependency_graph(
    deps: Dict[str, DependencyInfo],
) -> DependencyGraph:
    """
    Build a static dependency graph.
    """
    graph = DependencyGraph()

    for dep in deps.values():
        graph.add_node(dep)

    # Static approximation: assume runtime deps depend on build/dev deps
    runtime = [
        d.name for d in deps.values()
        if d.dependency_type == DependencyType.RUNTIME
    ]
    others = [
        d.name for d in deps.values()
        if d.dependency_type != DependencyType.RUNTIME
    ]

    for r in runtime:
        for o in others:
            graph.add_edge(r, o)

    return graph

# =============================================================================
# Dependency-level risk scoring
# =============================================================================

def compute_dependency_risk(dep: DependencyInfo) -> float:
    """
    Compute a risk score for a single dependency.
    """
    score = 0.0

    if dep.is_vulnerable():
        score += 0.5

    if dep.version and dep.version.startswith("0."):
        score += 0.2

    if dep.license in {LicenseType.GPL, LicenseType.PROPRIETARY}:
        score += 0.2

    if dep.dependency_type == DependencyType.OPTIONAL:
        score -= 0.1

    return min(1.0, round(score, 3))


def attach_dependency_risk_scores(
    graph: DependencyGraph,
) -> None:
    """
    Attach risk scores to dependency graph nodes.
    """
    for node in graph.nodes.values():
        node.risk_score = compute_dependency_risk(node.info)


# =============================================================================
# Freshness & maintenance heuristics
# =============================================================================

def estimate_dependency_freshness(
    dep: DependencyInfo,
) -> str:
    """
    Estimate freshness based on version semantics.
    """
    if not dep.version:
        return "unknown"

    if "dev" in dep.version or "alpha" in dep.version:
        return "experimental"

    if dep.version.startswith("0."):
        return "early"

    major = re.findall(r"\d+", dep.version)
    if major and int(major[0]) >= 1:
        return "stable"

    return "unknown"


def compute_freshness_summary(
    deps: Dict[str, DependencyInfo],
) -> Dict[str, int]:
    summary: Dict[str, int] = {}

    for dep in deps.values():
        status = estimate_dependency_freshness(dep)
        summary[status] = summary.get(status, 0) + 1

    return summary


# =============================================================================
# Policy & rule evaluation
# =============================================================================

@dataclass
class DependencyPolicy:
    max_vulnerable: int = 0
    disallowed_licenses: Set[LicenseType] = field(default_factory=set)
    allow_pre_release: bool = False


def evaluate_dependency_policy(
    analysis: DependencyAnalysis,
    *,
    policy: DependencyPolicy,
) -> List[str]:
    """
    Evaluate dependency analysis against a policy.
    """
    violations: List[str] = []

    if analysis.vulnerable_dependencies > policy.max_vulnerable:
        violations.append(
            f"Vulnerable dependencies exceed limit ({analysis.vulnerable_dependencies})"
        )

    for dep in analysis.dependencies.values():
        if dep.license in policy.disallowed_licenses:
            violations.append(
                f"Disallowed license detected: {dep.name} ({dep.license.value})"
            )

        if not policy.allow_pre_release:
            if dep.version and any(
                k in dep.version for k in ("alpha", "beta", "dev")
            ):
                violations.append(
                    f"Pre-release dependency detected: {dep.name}"
                )

    return violations


# =============================================================================
# Extended orchestration helpers
# =============================================================================

def analyze_dependencies_with_graph(
    repo_path: Path,
) -> Dict[str, object]:
    """
    Analyze dependencies and include graph-based insights.
    """
    analysis = analyze_dependency_files(repo_path)

    graph = build_dependency_graph(analysis.dependencies)
    attach_dependency_risk_scores(graph)

    freshness = compute_freshness_summary(analysis.dependencies)

    return {
        "summary": summarize_dependencies(analysis),
        "health_score": analysis.health_score,
        "freshness": freshness,
        "high_risk_dependencies": [
            node.name for node in graph.nodes.values()
            if node.risk_score >= 0.5
        ],
        "dependency_graph": {
            "nodes": len(graph.nodes),
            "edges": sum(len(n.dependencies) for n in graph.nodes.values()),
        },
        "recommendations": analysis.recommendations,
    }

# =============================================================================
# Ecosystem-specific heuristics & confidence scoring
# =============================================================================

@dataclass
class DependencyConfidence:
    """
    Represents confidence in correctness and stability of a dependency entry.
    """
    name: str
    source: DependencySource
    confidence_score: float
    reasons: List[str] = field(default_factory=list)


def compute_ecosystem_confidence(
    dep: DependencyInfo,
) -> DependencyConfidence:
    """
    Compute confidence score for a dependency based on ecosystem heuristics.
    """
    score = 1.0
    reasons: List[str] = []

    # Version presence
    if not dep.version:
        score -= 0.25
        reasons.append("missing_version")

    # Pre-release versions
    if dep.version and any(k in dep.version for k in ("alpha", "beta", "dev")):
        score -= 0.15
        reasons.append("pre_release_version")

    # Ecosystem-specific rules
    if dep.source == DependencySource.PYTHON:
        if dep.name.startswith("_"):
            score -= 0.1
            reasons.append("private_python_package")

    elif dep.source == DependencySource.JAVASCRIPT:
        if dep.name.startswith("@"):
            score -= 0.05
            reasons.append("scoped_package")

    elif dep.source == DependencySource.JVM:
        if ":" in dep.name:
            score -= 0.05
            reasons.append("multi_artifact_coordinate")

    # License uncertainty
    if dep.license == LicenseType.UNKNOWN:
        score -= 0.15
        reasons.append("unknown_license")

    return DependencyConfidence(
        name=dep.name,
        source=dep.source,
        confidence_score=max(0.0, round(score, 3)),
        reasons=reasons,
    )


def compute_confidence_summary(
    deps: Dict[str, DependencyInfo],
) -> Dict[str, object]:
    """
    Compute confidence metrics across all dependencies.
    """
    confidences = [
        compute_ecosystem_confidence(dep)
        for dep in deps.values()
    ]

    low_conf = [
        c for c in confidences if c.confidence_score < 0.6
    ]

    return {
        "average_confidence": round(
            sum(c.confidence_score for c in confidences) / len(confidences),
            3,
        ) if confidences else 1.0,
        "low_confidence_dependencies": len(low_conf),
        "details": [
            {
                "name": c.name,
                "score": c.confidence_score,
                "reasons": c.reasons,
            }
            for c in low_conf
        ],
    }

# =============================================================================
# Dependency conflict & shadowing detection
# =============================================================================

@dataclass
class DependencyConflict:
    """
    Represents a detected dependency conflict.
    """
    name: str
    conflict_type: str
    details: Dict[str, object]


def detect_version_conflicts(
    deps: Dict[str, DependencyInfo],
) -> List[DependencyConflict]:
    """
    Detect dependencies that appear with conflicting versions.
    """
    seen: Dict[str, Set[str]] = {}
    conflicts: List[DependencyConflict] = []

    for dep in deps.values():
        if not dep.version:
            continue
        key = dep.name.lower()
        seen.setdefault(key, set()).add(dep.version)

    for name, versions in seen.items():
        if len(versions) > 1:
            conflicts.append(
                DependencyConflict(
                    name=name,
                    conflict_type="version_conflict",
                    details={
                        "versions": sorted(versions),
                        "count": len(versions),
                    },
                )
            )

    return conflicts


def detect_dependency_type_conflicts(
    deps: Dict[str, DependencyInfo],
) -> List[DependencyConflict]:
    """
    Detect dependencies that appear as multiple dependency types.
    """
    seen: Dict[str, Set[DependencyType]] = {}
    conflicts: List[DependencyConflict] = []

    for dep in deps.values():
        key = dep.name.lower()
        seen.setdefault(key, set()).add(dep.dependency_type)

    for name, types in seen.items():
        if len(types) > 1:
            conflicts.append(
                DependencyConflict(
                    name=name,
                    conflict_type="dependency_type_conflict",
                    details={
                        "types": [t.value for t in types],
                    },
                )
            )

    return conflicts


def detect_ecosystem_shadowing(
    deps: Dict[str, DependencyInfo],
) -> List[DependencyConflict]:
    """
    Detect dependencies that exist across multiple ecosystems.
    """
    seen: Dict[str, Set[DependencySource]] = {}
    conflicts: List[DependencyConflict] = []

    for dep in deps.values():
        key = dep.name.lower()
        seen.setdefault(key, set()).add(dep.source)

    for name, sources in seen.items():
        if len(sources) > 1:
            conflicts.append(
                DependencyConflict(
                    name=name,
                    conflict_type="ecosystem_shadowing",
                    details={
                        "sources": [s.value for s in sources],
                        "count": len(sources),
                    },
                )
            )

    return conflicts


def compute_version_divergence(
    deps: Dict[str, DependencyInfo],
) -> Dict[str, float]:
    """
    Compute divergence score for dependencies with multiple versions.
    """
    divergence: Dict[str, float] = {}
    versions_map: Dict[str, List[str]] = {}

    for dep in deps.values():
        if dep.version:
            versions_map.setdefault(dep.name.lower(), []).append(dep.version)

    for name, versions in versions_map.items():
        if len(versions) <= 1:
            continue

        numeric_versions = []
        for v in versions:
            parts = re.findall(r"\d+", v)
            if parts:
                numeric_versions.append(int(parts[0]))

        if len(numeric_versions) > 1:
            diff = max(numeric_versions) - min(numeric_versions)
            divergence[name] = round(diff / max(numeric_versions), 3)

    return divergence


# =============================================================================
# Aggregated conflict analysis
# =============================================================================

def analyze_dependency_conflicts(
    deps: Dict[str, DependencyInfo],
) -> Dict[str, object]:
    """
    Perform full dependency conflict analysis.
    """
    version_conflicts = detect_version_conflicts(deps)
    type_conflicts = detect_dependency_type_conflicts(deps)
    shadowing_conflicts = detect_ecosystem_shadowing(deps)
    divergence = compute_version_divergence(deps)

    return {
        "total_conflicts": (
            len(version_conflicts)
            + len(type_conflicts)
            + len(shadowing_conflicts)
        ),
        "version_conflicts": [
            c.__dict__ for c in version_conflicts
        ],
        "type_conflicts": [
            c.__dict__ for c in type_conflicts
        ],
        "ecosystem_shadowing": [
            c.__dict__ for c in shadowing_conflicts
        ],
        "version_divergence": divergence,
    }

# =============================================================================
# Detailed findings & explainability engine
# =============================================================================

@dataclass
class DependencyFinding:
    """
    Represents a detailed finding for a single dependency.
    """
    name: str
    severity: str
    category: str
    message: str
    evidence: Dict[str, object]


def generate_dependency_findings(
    dep: DependencyInfo,
) -> List[DependencyFinding]:
    """
    Generate detailed findings for a single dependency.
    """
    findings: List[DependencyFinding] = []

    # Vulnerability findings
    for vuln in dep.vulnerabilities:
        findings.append(
            DependencyFinding(
                name=dep.name,
                severity=vuln.severity.value,
                category="vulnerability",
                message=f"Vulnerability detected: {vuln.identifier}",
                evidence={
                    "version": dep.version,
                    "description": vuln.description,
                },
            )
        )

    # License findings
    if dep.license in {LicenseType.GPL, LicenseType.PROPRIETARY}:
        findings.append(
            DependencyFinding(
                name=dep.name,
                severity="medium",
                category="license",
                message=f"Potentially restrictive license: {dep.license.value}",
                evidence={
                    "license": dep.license.value,
                },
            )
        )

    # Version findings
    if dep.version:
        if dep.version.startswith("0."):
            findings.append(
                DependencyFinding(
                    name=dep.name,
                    severity="medium",
                    category="stability",
                    message="Dependency uses major version zero",
                    evidence={
                        "version": dep.version,
                    },
                )
            )

        if any(k in dep.version for k in ("alpha", "beta", "dev")):
            findings.append(
                DependencyFinding(
                    name=dep.name,
                    severity="low",
                    category="stability",
                    message="Pre-release dependency version detected",
                    evidence={
                        "version": dep.version,
                    },
                )
            )

    # Dependency type findings
    if dep.dependency_type == DependencyType.OPTIONAL:
        findings.append(
            DependencyFinding(
                name=dep.name,
                severity="info",
                category="classification",
                message="Optional dependency",
                evidence={},
            )
        )

    return findings


def generate_all_findings(
    analysis: DependencyAnalysis,
) -> List[DependencyFinding]:
    """
    Generate findings for all dependencies.
    """
    all_findings: List[DependencyFinding] = []

    for dep in analysis.dependencies.values():
        all_findings.extend(generate_dependency_findings(dep))

    return all_findings


def summarize_findings(
    findings: List[DependencyFinding],
) -> Dict[str, int]:
    """
    Summarize findings by severity.
    """
    summary: Dict[str, int] = {}

    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1

    return summary


def explain_dependency_risk(
    dep: DependencyInfo,
) -> str:
    """
    Provide a human-readable explanation of dependency risk.
    """
    reasons: List[str] = []

    if dep.is_vulnerable():
        reasons.append("known vulnerabilities")

    if dep.version and dep.version.startswith("0."):
        reasons.append("major version zero")

    if dep.license in {LicenseType.GPL, LicenseType.PROPRIETARY}:
        reasons.append("restrictive license")

    if not dep.version:
        reasons.append("missing version pin")

    if not reasons:
        return "No significant risk factors identified"

    return "Risk due to: " + ", ".join(reasons)


def build_explainability_report(
    analysis: DependencyAnalysis,
) -> Dict[str, object]:
    """
    Build an explainability-focused report for dependencies.
    """
    findings = generate_all_findings(analysis)

    return {
        "finding_summary": summarize_findings(findings),
        "findings": [
            {
                "dependency": f.name,
                "severity": f.severity,
                "category": f.category,
                "message": f.message,
                "evidence": f.evidence,
            }
            for f in findings
        ],
        "explanations": {
            dep.name: explain_dependency_risk(dep)
            for dep in analysis.dependencies.values()
        },
    }


# =============================================================================
# Extended public API with explainability
# =============================================================================

def analyze_repository_dependencies_verbose(
    repo_path: Path,
) -> Dict[str, object]:
    """
    Extended dependency analysis including explainability details.
    """
    analysis = analyze_dependency_files(repo_path)
    explainability = build_explainability_report(analysis)

    return {
        "summary": summarize_dependencies(analysis),
        "health_score": analysis.health_score,
        "recommendations": analysis.recommendations,
        "explainability": explainability,
    }


# =============================================================================
# End of dependency analyzer
# =============================================================================
