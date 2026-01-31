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

# =============================================================================
# Summaries & filters
# =============================================================================

def test_summarize_scan_result(fs_repo: Path):
    result = scan_filesystem(fs_repo)
    summary = summarize_scan_result(result)

    assert summary["total_files"] > 0
    assert summary["total_size_bytes"] > 0


def test_filter_large_files(fs_repo: Path):
    result = scan_filesystem(fs_repo)
    large = filter_large_files(result.files, min_size_bytes=1)
    assert len(large) > 0


def test_filter_by_depth(fs_repo: Path):
    result = scan_filesystem(fs_repo)
    shallow = filter_by_depth(result.directories, max_depth=1)
    assert all(d.depth <= 1 for d in shallow)


def test_sort_files_by_size(fs_repo: Path):
    result = scan_filesystem(fs_repo)
    sorted_files = sort_files_by_size(result.files)
    assert sorted_files[0].size_bytes >= sorted_files[-1].size_bytes


def test_sort_directories_by_size(fs_repo: Path):
    result = scan_filesystem(fs_repo)
    aggregated = aggregate_directory_metadata(
        result.files, result.directories
    )
    sorted_dirs = sort_directories_by_size(aggregated)
    assert sorted_dirs[0].total_size_bytes >= sorted_dirs[-1].total_size_bytes


# =============================================================================
# Limits & truncation
# =============================================================================

def test_enforce_limits_on_result(fs_repo: Path):
    result = scan_filesystem(fs_repo)
    limited = enforce_limits_on_result(result, max_files=1)

    assert len(limited.files) == 1


def test_truncate_errors():
    result = ScanResult(errors=[str(i) for i in range(100)])
    truncated = truncate_errors(result, max_errors=10)
    assert len(truncated.errors) == 10


# =============================================================================
# Orchestration
# =============================================================================

def test_perform_scan_basic(fs_repo: Path):
    result, meta = perform_scan(fs_repo)

    assert meta["files_scanned"] > 0
    assert meta["elapsed_seconds"] >= 0.0


def test_perform_scan_no_permissions(fs_repo: Path):
    result, meta = perform_scan(
        fs_repo,
        check_permissions=False,
    )
    assert meta["files_scanned"] > 0


# =============================================================================
# Report builders
# =============================================================================

def test_build_scan_report(fs_repo: Path):
    result = scan_filesystem(fs_repo)
    report = build_scan_report(result)

    assert "summary" in report
    assert "files" in report
    assert "directories" in report


def test_build_compact_scan_report(fs_repo: Path):
    result = scan_filesystem(fs_repo)
    report = build_compact_scan_report(result)

    assert "total_files" in report
    assert "total_size_bytes" in report


# =============================================================================
# Convenience wrappers
# =============================================================================

def test_scan_repository_quick(fs_repo: Path):
    report = scan_repository_quick(fs_repo)
    assert "elapsed_seconds" in report
    assert report["total_files"] > 0


def test_scan_repository_detailed(fs_repo: Path):
    report = scan_repository_detailed(fs_repo)
    assert "files" in report
    assert "directories" in report
    assert "metadata" in report