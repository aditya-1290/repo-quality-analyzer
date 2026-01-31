"""
Repository Utility Functions

This module provides a comprehensive set of filesystem, path, validation,
and repository inspection utilities. It is intentionally verbose and
defensive, reflecting patterns commonly found in internal developer
platforms and tooling codebases.

This file is designed to grow large by aggregating many related helpers
into a single domain-focused utility module.
"""

from __future__ import annotations

import os
import sys
import stat
import time
import json
import hashlib
import logging
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
)

# =============================================================================
# Logging
# =============================================================================

LOGGER_NAME = "repo_quality.utils"
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(logging.INFO)


# =============================================================================
# Exceptions
# =============================================================================

class RepositoryUtilsError(Exception):
    """
    Base exception for repository utility errors.
    """


class InvalidRepositoryError(RepositoryUtilsError):
    """
    Raised when a path does not represent a valid repository.
    """


class FileReadError(RepositoryUtilsError):
    """
    Raised when a file cannot be read safely.
    """


# =============================================================================
# Path & repository validation
# =============================================================================

def ensure_path_exists(path: Path) -> None:
    """
    Ensure that a given path exists.

    Args:
        path: Path to validate

    Raises:
        InvalidRepositoryError if path does not exist
    """
    if not path.exists():
        raise InvalidRepositoryError(f"Path does not exist: {path}")


def ensure_is_directory(path: Path) -> None:
    """
    Ensure that a given path is a directory.

    Args:
        path: Path to validate

    Raises:
        InvalidRepositoryError if path is not a directory
    """
    if not path.is_dir():
        raise InvalidRepositoryError(f"Path is not a directory: {path}")


def validate_repository_root(path: Path) -> None:
    """
    Validate that a path represents a plausible repository root.

    This does not enforce a specific VCS but checks for basic sanity.
    """
    ensure_path_exists(path)
    ensure_is_directory(path)

    # Soft checks (warnings, not errors)
    if not any((path / name).exists() for name in [".git", ".hg", ".svn"]):
        logger.warning(
            "Repository root %s does not appear to contain VCS metadata",
            path,
        )


# =============================================================================
# Directory walking utilities
# =============================================================================

DEFAULT_EXCLUDED_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".idea",
    ".vscode",
}


def should_exclude_directory(
    dir_name: str,
    extra_excludes: Optional[Iterable[str]] = None,
) -> bool:
    """
    Determine whether a directory should be excluded during traversal.
    """
    excludes = set(DEFAULT_EXCLUDED_DIRS)
    if extra_excludes:
        excludes.update(extra_excludes)
    return dir_name in excludes


def walk_repository_tree(
    root: Path,
    *,
    exclude_dirs: Optional[Iterable[str]] = None,
) -> Iterator[Path]:
    """
    Recursively walk a repository directory tree, yielding all paths.

    Args:
        root: Root directory to walk
        exclude_dirs: Additional directory names to exclude

    Yields:
        Path objects for files and directories
    """
    for current_root, dirs, files in os.walk(root):
        root_path = Path(current_root)

        # Modify dirs in-place to control recursion
        dirs[:] = [
            d for d in dirs
            if not should_exclude_directory(d, exclude_dirs)
        ]

        for d in dirs:
            yield root_path / d

        for f in files:
            yield root_path / f


# =============================================================================
# File system inspection helpers
# =============================================================================

def is_binary_file(path: Path, sample_size: int = 1024) -> bool:
    """
    Heuristically determine whether a file is binary.

    This reads a small sample of the file and looks for null bytes.
    """
    try:
        with path.open("rb") as handle:
            chunk = handle.read(sample_size)
            return b"\x00" in chunk
    except OSError:
        return False


def is_readable_file(path: Path) -> bool:
    """
    Check whether a file is readable by the current process.
    """
    try:
        mode = path.stat().st_mode
        return bool(mode & stat.S_IRUSR)
    except OSError:
        return False


def safe_read_text(
    path: Path,
    *,
    encoding: str = "utf-8",
    errors: str = "ignore",
    max_bytes: Optional[int] = None,
) -> str:
    """
    Safely read a text file with multiple guards.

    Args:
        path: File path
        encoding: Text encoding
        errors: Error handling strategy
        max_bytes: Optional maximum bytes to read

    Returns:
        File contents as string

    Raises:
        FileReadError if file cannot be read
    """
    if not path.exists():
        raise FileReadError(f"File does not exist: {path}")

    if not path.is_file():
        raise FileReadError(f"Path is not a file: {path}")

    if is_binary_file(path):
        return ""

    try:
        if max_bytes is not None:
            with path.open("rb") as handle:
                raw = handle.read(max_bytes)
            return raw.decode(encoding, errors=errors)

        return path.read_text(encoding=encoding, errors=errors)

    except Exception as exc:
        raise FileReadError(f"Failed to read file {path}: {exc}") from exc


# =============================================================================
# File hashing & size utilities
# =============================================================================

def compute_file_hash(
    path: Path,
    *,
    algorithm: str = "sha256",
    chunk_size: int = 8192,
) -> str:
    """
    Compute a cryptographic hash for a file.

    Args:
        path: File path
        algorithm: Hash algorithm name
        chunk_size: Bytes per read

    Returns:
        Hex digest string
    """
    try:
        hasher = hashlib.new(algorithm)
    except ValueError as exc:
        raise RepositoryUtilsError(
            f"Unsupported hash algorithm: {algorithm}"
        ) from exc

    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError as exc:
        raise FileReadError(f"Failed to hash file {path}: {exc}") from exc


def get_file_size_bytes(path: Path) -> int:
    """
    Return file size in bytes, or zero on failure.
    """
    try:
        return path.stat().st_size
    except OSError:
        return 0


def get_directory_size_bytes(root: Path) -> int:
    """
    Compute total size of all files under a directory.
    """
    total = 0
    for item in walk_repository_tree(root):
        if item.is_file():
            total += get_file_size_bytes(item)
    return total


# =============================================================================
# Basic serialization helpers
# =============================================================================

def serialize_to_json(
    data: Any,
    *,
    indent: int = 2,
    sort_keys: bool = True,
) -> str:
    """
    Serialize arbitrary data to JSON.
    """
    try:
        return json.dumps(data, indent=indent, sort_keys=sort_keys)
    except TypeError:
        return json.dumps(str(data))


def write_json_file(
    path: Path,
    data: Any,
    *,
    indent: int = 2,
) -> None:
    """
    Write data to a JSON file safely.
    """
    try:
        content = serialize_to_json(data, indent=indent)
        path.write_text(content, encoding="utf-8")
    except Exception as exc:
        raise RepositoryUtilsError(
            f"Failed to write JSON file {path}: {exc}"
        ) from exc

# =============================================================================
# Language detection & file classification
# =============================================================================

LANGUAGE_BY_EXTENSION: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".cpp": "cpp",
    ".c": "c",
    ".h": "c_header",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".sh": "shell",
    ".ps1": "powershell",
    ".sql": "sql",
    ".html": "html",
    ".css": "css",
    ".md": "markdown",
    ".json": "json",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".xml": "xml",
}

TEST_FILE_MARKERS: Tuple[str, ...] = (
    "test_",
    "_test",
    "/tests/",
    "/__tests__/",
    ".spec.",
    ".test.",
)

CONFIG_FILE_NAMES: Set[str] = {
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "package.json",
    "pom.xml",
    "build.gradle",
    "gradle.properties",
    ".editorconfig",
    ".gitignore",
    ".gitattributes",
}

DOC_EXTENSIONS: Set[str] = {
    ".md",
    ".rst",
    ".txt",
    ".adoc",
}


def detect_language_from_extension(path: Path) -> Optional[str]:
    """
    Detect programming language based on file extension.

    Returns:
        Language name or None if unknown.
    """
    return LANGUAGE_BY_EXTENSION.get(path.suffix.lower())


def is_test_file(path: Path) -> bool:
    """
    Determine whether a file is likely a test file based on path heuristics.
    """
    lower = str(path).lower()
    return any(marker in lower for marker in TEST_FILE_MARKERS)


def is_config_file(path: Path) -> bool:
    """
    Determine whether a file is a configuration file.
    """
    return path.name in CONFIG_FILE_NAMES


def is_documentation_file(path: Path) -> bool:
    """
    Determine whether a file is a documentation file.
    """
    return path.suffix.lower() in DOC_EXTENSIONS


def classify_file(path: Path) -> str:
    """
    Classify a file into a high-level category.

    Categories:
        - source
        - test
        - config
        - docs
        - binary
        - unknown
    """
    if not path.is_file():
        return "unknown"

    if is_binary_file(path):
        return "binary"

    if is_test_file(path):
        return "test"

    if is_config_file(path):
        return "config"

    if is_documentation_file(path):
        return "docs"

    if detect_language_from_extension(path):
        return "source"

    return "unknown"


# =============================================================================
# Repository statistics & aggregation
# =============================================================================

def aggregate_language_stats(
    root: Path,
    *,
    exclude_dirs: Optional[Iterable[str]] = None,
) -> Dict[str, int]:
    """
    Aggregate counts of files per detected programming language.
    """
    stats: Dict[str, int] = {}

    for item in walk_repository_tree(root, exclude_dirs=exclude_dirs):
        if not item.is_file():
            continue

        language = detect_language_from_extension(item)
        if not language:
            continue

        stats[language] = stats.get(language, 0) + 1

    return dict(sorted(stats.items()))


def aggregate_file_categories(
    root: Path,
    *,
    exclude_dirs: Optional[Iterable[str]] = None,
) -> Dict[str, int]:
    """
    Count files by classification category.
    """
    categories: Dict[str, int] = {}

    for item in walk_repository_tree(root, exclude_dirs=exclude_dirs):
        if not item.is_file():
            continue

        category = classify_file(item)
        categories[category] = categories.get(category, 0) + 1

    return dict(sorted(categories.items()))


def collect_directory_depth_stats(root: Path) -> Dict[int, int]:
    """
    Collect statistics on directory depth distribution.
    """
    depth_stats: Dict[int, int] = {}

    for item in walk_repository_tree(root):
        try:
            depth = len(item.relative_to(root).parts)
        except ValueError:
            continue

        depth_stats[depth] = depth_stats.get(depth, 0) + 1

    return dict(sorted(depth_stats.items()))


# =============================================================================
# Line counting utilities
# =============================================================================

def count_lines_in_text(text: str) -> Tuple[int, int, int]:
    """
    Count total, blank, and non-blank lines in text.

    Returns:
        (total_lines, blank_lines, non_blank_lines)
    """
    total = 0
    blank = 0

    for line in text.splitlines():
        total += 1
        if not line.strip():
            blank += 1

    return total, blank, total - blank


def count_lines_in_file(
    path: Path,
    *,
    max_bytes: Optional[int] = None,
) -> Tuple[int, int, int]:
    """
    Count lines in a single file safely.
    """
    try:
        content = safe_read_text(path, max_bytes=max_bytes)
        return count_lines_in_text(content)
    except FileReadError:
        return 0, 0, 0


def count_repository_lines(
    root: Path,
    *,
    exclude_dirs: Optional[Iterable[str]] = None,
    max_bytes_per_file: Optional[int] = None,
) -> Dict[str, int]:
    """
    Count total, blank, and non-blank lines across a repository.
    """
    totals = {
        "total_lines": 0,
        "blank_lines": 0,
        "non_blank_lines": 0,
        "files_counted": 0,
    }

    for item in walk_repository_tree(root, exclude_dirs=exclude_dirs):
        if not item.is_file():
            continue

        total, blank, non_blank = count_lines_in_file(
            item,
            max_bytes=max_bytes_per_file,
        )

        totals["total_lines"] += total
        totals["blank_lines"] += blank
        totals["non_blank_lines"] += non_blank
        totals["files_counted"] += 1

    return totals


# =============================================================================
# Progress & timing helpers
# =============================================================================

class ProgressTracker:
    """
    Lightweight progress tracker for long-running repository operations.
    """

    def __init__(self, *, report_every: float = 1.0) -> None:
        self.start_time = time.time()
        self.last_report = self.start_time
        self.report_every = report_every
        self.items_processed = 0

    def increment(self, count: int = 1) -> None:
        """
        Increment processed item count and emit progress if needed.
        """
        self.items_processed += count
        now = time.time()

        if now - self.last_report >= self.report_every:
            self.last_report = now
            logger.info(
                "Processed %d items (elapsed %.2fs)",
                self.items_processed,
                now - self.start_time,
            )

    def snapshot(self) -> Dict[str, Any]:
        """
        Return a snapshot of current progress.
        """
        now = time.time()
        return {
            "items_processed": self.items_processed,
            "elapsed_seconds": round(now - self.start_time, 2),
        }


# =============================================================================
# Summary builders
# =============================================================================

def build_repository_summary(
    root: Path,
    *,
    exclude_dirs: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """
    Build a high-level summary of repository characteristics.
    """
    summary: Dict[str, Any] = {}

    summary["total_size_bytes"] = get_directory_size_bytes(root)
    summary["languages"] = aggregate_language_stats(
        root, exclude_dirs=exclude_dirs
    )
    summary["file_categories"] = aggregate_file_categories(
        root, exclude_dirs=exclude_dirs
    )
    summary["directory_depths"] = collect_directory_depth_stats(root)
    summary["line_counts"] = count_repository_lines(
        root, exclude_dirs=exclude_dirs
    )

    return summary
