import os
import time
from pathlib import Path
from datetime import datetime

import pytest

from src.utils.filesystem_scanner import (
    FileMetadata,
    DirectoryMetadata,
    ScanLimits,
    ScanResult,
    is_executable,
    collect_file_metadata,
    calculate_depth,
    scan_filesystem,
    has_read_permission,
    has_execute_permission,
    is_safe_to_scan,
    aggregate_directory_metadata,
    scan_with_permissions,
    scan_without_permissions,
    summarize_scan_result,
    filter_large_files,
    filter_by_depth,
    sort_files_by_size,
    sort_directories_by_size,
    enforce_limits_on_result,
    truncate_errors,
    perform_scan,
    build_scan_report,
    build_compact_scan_report,
    scan_repository_quick,
    scan_repository_detailed,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def fs_repo(tmp_path: Path) -> Path:
    """
    Create a fake filesystem tree for scanner testing.
    """
    root = tmp_path / "repo"
    root.mkdir()

    # directories
    src = root / "src"
    src.mkdir()

    deep = src / "deep"
    deep.mkdir()

    tests = root / "tests"
    tests.mkdir()

    # files
    (root / "README.md").write_text("hello\n", encoding="utf-8")
    (src / "main.py").write_text("print('hi')\n", encoding="utf-8")
    (deep / "util.py").write_text("x = 1\n", encoding="utf-8")
    (tests / "test_main.py").write_text("def test_ok(): pass\n", encoding="utf-8")

    return root


# =============================================================================
# Basic helpers
# =============================================================================

def test_is_executable(tmp_path: Path):
    file = tmp_path / "exec.sh"
    file.write_text("echo hi", encoding="utf-8")
    file.chmod(0o755)
    assert is_executable(file) is True


def test_collect_file_metadata(fs_repo: Path):
    file = fs_repo / "src" / "main.py"
    meta = collect_file_metadata(file)

    assert isinstance(meta, FileMetadata)
    assert meta.size_bytes > 0
    assert meta.is_symlink is False
    assert isinstance(meta.last_modified, datetime)


def test_calculate_depth(fs_repo: Path):
    root = fs_repo
    deep_file = fs_repo / "src" / "deep" / "util.py"
    depth = calculate_depth(root, deep_file)
    assert depth >= 3


# =============================================================================
# Core scanning
# =============================================================================

def test_scan_filesystem_basic(fs_repo: Path):
    result = scan_filesystem(fs_repo)

    assert isinstance(result, ScanResult)
    assert len(result.files) >= 3
    assert len(result.directories) >= 3
    assert result.errors == []


def test_scan_filesystem_with_limits(fs_repo: Path):
    limits = ScanLimits(max_files=1)
    result = scan_filesystem(fs_repo, limits=limits)
    assert len(result.files) == 1


def test_scan_filesystem_depth_limit(fs_repo: Path):
    limits = ScanLimits(max_depth=1)
    result = scan_filesystem(fs_repo, limits=limits)

    for d in result.directories:
        assert d.depth <= 1


# =============================================================================
# Permission helpers
# =============================================================================

def test_has_read_permission(fs_repo: Path):
    assert has_read_permission(fs_repo / "README.md") is True


def test_has_execute_permission(fs_repo: Path):
    assert has_execute_permission(fs_repo) is True


def test_is_safe_to_scan_symlink(tmp_path: Path):
    target = tmp_path / "target.txt"
    target.write_text("x", encoding="utf-8")

    link = tmp_path / "link.txt"
    link.symlink_to(target)

    assert is_safe_to_scan(link, follow_symlinks=False) is False
    assert is_safe_to_scan(link, follow_symlinks=True) is True


# =============================================================================
# Aggregation
# =============================================================================

def test_aggregate_directory_metadata(fs_repo: Path):
    result = scan_filesystem(fs_repo)
    aggregated = aggregate_directory_metadata(
        result.files,
        result.directories,
    )

    assert len(aggregated) == len(result.directories)
    assert any(d.total_files > 0 for d in aggregated)


# =============================================================================
# Scan variants
# =============================================================================

def test_scan_with_permissions(fs_repo: Path):
    result = scan_with_permissions(fs_repo)
    assert len(result.files) > 0


def test_scan_without_permissions(fs_repo: Path):
    result = scan_without_permissions(fs_repo)
    assert len(result.files) > 0

