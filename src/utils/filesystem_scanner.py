"""
Filesystem Scanner Utilities

This module provides robust, defensive utilities for scanning filesystem
trees, collecting metadata, and safely traversing large repositories.
"""

from __future__ import annotations

import os
import stat
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from src.utils.repository_utils import (
    walk_repository_tree,
    get_file_size_bytes,
    RepositoryUtilsError,
)

LOGGER_NAME = "repo_quality.fs_scanner"
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(logging.INFO)


# =============================================================================
# Data models
# =============================================================================

@dataclass
class FileMetadata:
    path: str
    size_bytes: int
    is_symlink: bool
    is_executable: bool
    last_modified: datetime


@dataclass
class DirectoryMetadata:
    path: str
    total_files: int = 0
    total_size_bytes: int = 0
    depth: int = 0


@dataclass
class ScanLimits:
    max_depth: Optional[int] = None
    max_files: Optional[int] = None
    follow_symlinks: bool = False


@dataclass
class ScanResult:
    files: List[FileMetadata] = field(default_factory=list)
    directories: List[DirectoryMetadata] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# =============================================================================
# Core scanning logic
# =============================================================================

def is_executable(path: Path) -> bool:
    """
    Determine whether a file is executable.
    """
    try:
        mode = path.stat().st_mode
        return bool(mode & stat.S_IXUSR)
    except OSError:
        return False


def collect_file_metadata(path: Path) -> FileMetadata:
    """
    Collect metadata for a single file.
    """
    try:
        stat_info = path.stat()
        return FileMetadata(
            path=str(path),
            size_bytes=stat_info.st_size,
            is_symlink=path.is_symlink(),
            is_executable=is_executable(path),
            last_modified=datetime.fromtimestamp(stat_info.st_mtime),
        )
    except OSError as exc:
        raise RepositoryUtilsError(
            f"Failed to stat file {path}: {exc}"
        ) from exc


def calculate_depth(root: Path, path: Path) -> int:
    """
    Calculate directory depth relative to root.
    """
    try:
        return len(path.relative_to(root).parts)
    except ValueError:
        return 0


def scan_filesystem(
    root: Path,
    *,
    limits: Optional[ScanLimits] = None,
    exclude_dirs: Optional[Iterable[str]] = None,
) -> ScanResult:
    """
    Scan filesystem tree and collect file & directory metadata.
    """
    limits = limits or ScanLimits()
    result = ScanResult()

    files_seen = 0

    for item in walk_repository_tree(root, exclude_dirs=exclude_dirs):
        try:
            depth = calculate_depth(root, item)

            if limits.max_depth is not None and depth > limits.max_depth:
                continue

            if item.is_file():
                if limits.max_files is not None and files_seen >= limits.max_files:
                    break

                if item.is_symlink() and not limits.follow_symlinks:
                    continue

                metadata = collect_file_metadata(item)
                result.files.append(metadata)
                files_seen += 1

            elif item.is_dir():
                result.directories.append(
                    DirectoryMetadata(
                        path=str(item),
                        depth=depth,
                    )
                )

        except Exception as exc:  # noqa
            logger.warning("Scan error on %s: %s", item, exc)
            result.errors.append(str(exc))

    return result
