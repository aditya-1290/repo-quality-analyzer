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
