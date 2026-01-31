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
