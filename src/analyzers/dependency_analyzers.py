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
