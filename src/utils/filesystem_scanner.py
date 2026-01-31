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
import time

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

# =============================================================================
# Permission & safety helpers
# =============================================================================

def has_read_permission(path: Path) -> bool:
    """
    Check whether the current process can read the given path.
    """
    try:
        return os.access(path, os.R_OK)
    except OSError:
        return False


def has_execute_permission(path: Path) -> bool:
    """
    Check whether the current process can execute (enter) the given path.
    """
    try:
        return os.access(path, os.X_OK)
    except OSError:
        return False


def is_safe_to_scan(path: Path, *, follow_symlinks: bool = False) -> bool:
    """
    Determine whether a path is safe to scan based on permissions and symlinks.
    """
    if path.is_symlink() and not follow_symlinks:
        return False

    if path.is_dir():
        return has_read_permission(path) and has_execute_permission(path)

    if path.is_file():
        return has_read_permission(path)

    return False


# =============================================================================
# Directory aggregation
# =============================================================================

def initialize_directory_index(
    directories: Iterable[DirectoryMetadata],
) -> Dict[str, DirectoryMetadata]:
    """
    Initialize a directory index keyed by directory path.
    """
    index: Dict[str, DirectoryMetadata] = {}
    for d in directories:
        index[d.path] = DirectoryMetadata(
            path=d.path,
            depth=d.depth,
            total_files=0,
            total_size_bytes=0,
        )
    return index


def assign_file_to_directory(
    file_meta: FileMetadata,
    dir_index: Dict[str, DirectoryMetadata],
) -> None:
    """
    Assign file metadata to its nearest parent directory in the index.
    """
    file_path = Path(file_meta.path)

    for parent in [file_path.parent] + list(file_path.parents):
        parent_str = str(parent)
        if parent_str in dir_index:
            entry = dir_index[parent_str]
            entry.total_files += 1
            entry.total_size_bytes += file_meta.size_bytes
            return


def aggregate_directory_metadata(
    files: List[FileMetadata],
    directories: List[DirectoryMetadata],
) -> List[DirectoryMetadata]:
    """
    Aggregate file statistics into directory metadata entries.
    """
    index = initialize_directory_index(directories)

    for f in files:
        assign_file_to_directory(f, index)

    return list(index.values())


# =============================================================================
# Advanced scanning variants
# =============================================================================

def scan_with_permissions(
    root: Path,
    *,
    limits: Optional[ScanLimits] = None,
    exclude_dirs: Optional[Iterable[str]] = None,
) -> ScanResult:
    """
    Scan filesystem while explicitly checking permissions.
    """
    limits = limits or ScanLimits()
    result = ScanResult()

    files_seen = 0

    for item in walk_repository_tree(root, exclude_dirs=exclude_dirs):
        try:
            if not is_safe_to_scan(item, follow_symlinks=limits.follow_symlinks):
                continue

            depth = calculate_depth(root, item)
            if limits.max_depth is not None and depth > limits.max_depth:
                continue

            if item.is_file():
                if limits.max_files is not None and files_seen >= limits.max_files:
                    break

                meta = collect_file_metadata(item)
                result.files.append(meta)
                files_seen += 1

            elif item.is_dir():
                result.directories.append(
                    DirectoryMetadata(
                        path=str(item),
                        depth=depth,
                    )
                )

        except Exception as exc:  # noqa
            logger.error("Permission scan error on %s: %s", item, exc)
            result.errors.append(str(exc))

    return result


def scan_without_permissions(
    root: Path,
    *,
    limits: Optional[ScanLimits] = None,
    exclude_dirs: Optional[Iterable[str]] = None,
) -> ScanResult:
    """
    Scan filesystem without permission checks (best-effort mode).
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

                meta = collect_file_metadata(item)
                result.files.append(meta)
                files_seen += 1

            elif item.is_dir():
                result.directories.append(
                    DirectoryMetadata(
                        path=str(item),
                        depth=depth,
                    )
                )

        except Exception as exc:  # noqa
            logger.debug("Best-effort scan error on %s: %s", item, exc)
            result.errors.append(str(exc))

    return result


# =============================================================================
# Intermediate summaries & helpers
# =============================================================================

def summarize_scan_result(result: ScanResult) -> Dict[str, Any]:
    """
    Build a lightweight summary from a ScanResult.
    """
    total_size = sum(f.size_bytes for f in result.files)

    return {
        "total_files": len(result.files),
        "total_directories": len(result.directories),
        "total_size_bytes": total_size,
        "errors_count": len(result.errors),
    }


def filter_large_files(
    files: List[FileMetadata],
    *,
    min_size_bytes: int,
) -> List[FileMetadata]:
    """
    Filter files larger than a given size.
    """
    return [f for f in files if f.size_bytes >= min_size_bytes]


def filter_by_depth(
    directories: List[DirectoryMetadata],
    *,
    max_depth: int,
) -> List[DirectoryMetadata]:
    """
    Filter directories deeper than max_depth.
    """
    return [d for d in directories if d.depth <= max_depth]


def sort_files_by_size(
    files: List[FileMetadata],
    *,
    descending: bool = True,
) -> List[FileMetadata]:
    """
    Sort files by size.
    """
    return sorted(files, key=lambda f: f.size_bytes, reverse=descending)


def sort_directories_by_size(
    directories: List[DirectoryMetadata],
    *,
    descending: bool = True,
) -> List[DirectoryMetadata]:
    """
    Sort directories by aggregated size.
    """
    return sorted(
        directories,
        key=lambda d: d.total_size_bytes,
        reverse=descending,
    )

# =============================================================================
# Limits enforcement & helpers
# =============================================================================

def enforce_limits_on_result(
    result: ScanResult,
    *,
    max_files: Optional[int] = None,
    max_directories: Optional[int] = None,
) -> ScanResult:
    """
    Enforce post-scan limits on a ScanResult.

    This is useful when scans are executed in best-effort mode and limits
    must be applied after traversal.
    """
    if max_files is not None and len(result.files) > max_files:
        result.files = result.files[:max_files]

    if max_directories is not None and len(result.directories) > max_directories:
        result.directories = result.directories[:max_directories]

    return result


def truncate_errors(
    result: ScanResult,
    *,
    max_errors: int = 50,
) -> ScanResult:
    """
    Truncate the error list to a maximum number of entries.
    """
    if len(result.errors) > max_errors:
        result.errors = result.errors[:max_errors]
    return result


# =============================================================================
# Timing & instrumentation
# =============================================================================

class ScanTimer:
    """
    Timer utility for filesystem scans.
    """

    def __init__(self) -> None:
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None

    def start(self) -> None:
        self.started_at = time.time()

    def stop(self) -> None:
        self.finished_at = time.time()

    @property
    def elapsed_seconds(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.finished_at if self.finished_at is not None else time.time()
        return round(end - self.started_at, 4)


# =============================================================================
# Scan orchestration
# =============================================================================

def perform_scan(
    root: Path,
    *,
    limits: Optional[ScanLimits] = None,
    exclude_dirs: Optional[Iterable[str]] = None,
    check_permissions: bool = True,
    max_errors: Optional[int] = None,
) -> Tuple[ScanResult, Dict[str, Any]]:
    """
    Perform a filesystem scan with orchestration, timing, and summaries.

    Returns:
        (ScanResult, metadata)
    """
    timer = ScanTimer()
    timer.start()

    if check_permissions:
        result = scan_with_permissions(
            root,
            limits=limits,
            exclude_dirs=exclude_dirs,
        )
    else:
        result = scan_without_permissions(
            root,
            limits=limits,
            exclude_dirs=exclude_dirs,
        )

    # Aggregate directory metadata
    try:
        aggregated_dirs = aggregate_directory_metadata(
            result.files,
            result.directories,
        )
        result.directories = aggregated_dirs
    except Exception as exc:  # noqa
        logger.warning("Failed to aggregate directories: %s", exc)
        result.errors.append(str(exc))

    if limits:
        result = enforce_limits_on_result(
            result,
            max_files=limits.max_files,
        )

    if max_errors is not None:
        result = truncate_errors(result, max_errors=max_errors)

    timer.stop()

    metadata = {
        "elapsed_seconds": timer.elapsed_seconds,
        "files_scanned": len(result.files),
        "directories_scanned": len(result.directories),
        "errors_count": len(result.errors),
    }

    return result, metadata


# =============================================================================
# Report builders
# =============================================================================

def build_scan_report(
    result: ScanResult,
    *,
    include_files: bool = True,
    include_directories: bool = True,
    include_errors: bool = True,
) -> Dict[str, Any]:
    """
    Build a structured report from a ScanResult.
    """
    report: Dict[str, Any] = {}

    report["summary"] = summarize_scan_result(result)

    if include_files:
        report["files"] = [
            {
                "path": f.path,
                "size_bytes": f.size_bytes,
                "is_symlink": f.is_symlink,
                "is_executable": f.is_executable,
                "last_modified": f.last_modified.isoformat(),
            }
            for f in result.files
        ]

    if include_directories:
        report["directories"] = [
            {
                "path": d.path,
                "depth": d.depth,
                "total_files": d.total_files,
                "total_size_bytes": d.total_size_bytes,
            }
            for d in result.directories
        ]

    if include_errors:
        report["errors"] = list(result.errors)

    return report


def build_compact_scan_report(
    result: ScanResult,
) -> Dict[str, Any]:
    """
    Build a compact report intended for CLI or logging output.
    """
    summary = summarize_scan_result(result)
    return {
        "total_files": summary["total_files"],
        "total_directories": summary["total_directories"],
        "total_size_bytes": summary["total_size_bytes"],
        "errors": summary["errors_count"],
    }


# =============================================================================
# Convenience wrappers
# =============================================================================

def scan_repository_quick(
    root: Path,
    *,
    exclude_dirs: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """
    Perform a quick filesystem scan and return a compact report.
    """
    result, meta = perform_scan(
        root,
        exclude_dirs=exclude_dirs,
        check_permissions=False,
    )

    report = build_compact_scan_report(result)
    report["elapsed_seconds"] = meta["elapsed_seconds"]
    return report


def scan_repository_detailed(
    root: Path,
    *,
    limits: Optional[ScanLimits] = None,
    exclude_dirs: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """
    Perform a detailed filesystem scan and return a full report.
    """
    result, meta = perform_scan(
        root,
        limits=limits,
        exclude_dirs=exclude_dirs,
        check_permissions=True,
        max_errors=100,
    )

    report = build_scan_report(result)
    report["metadata"] = meta
    return report


# =============================================================================
# End of module
# =============================================================================
