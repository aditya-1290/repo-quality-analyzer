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
# End of dependency analyzer
# =============================================================================
