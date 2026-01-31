import os
import time
import json
import hashlib
from pathlib import Path

import pytest

from src.utils.repository_utils import (
    ensure_path_exists,
    ensure_is_directory,
    validate_repository_root,
    RepositoryUtilsError,
    InvalidRepositoryError,
    FileReadError,
    safe_read_text,
    is_binary_file,
    compute_file_hash,
    get_file_size_bytes,
    get_directory_size_bytes,
    detect_language_from_extension,
    is_test_file,
    is_config_file,
    is_documentation_file,
    classify_file,
    aggregate_language_stats,
    aggregate_file_categories,
    count_lines_in_text,
    count_lines_in_file,
    count_repository_lines,
    IgnoreRules,
    retry,
    guard,
    Timer,
    SimpleCache,
    build_repository_summary,
    build_extended_repository_summary,
    summarize_repository_quick,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def temp_repo(tmp_path: Path) -> Path:
    """
    Create a fake repository structure for testing.
    """
    repo = tmp_path / "repo"
    repo.mkdir()

    # source files
    (repo / "main.py").write_text("print('hello')\n", encoding="utf-8")
    (repo / "util.js").write_text("console.log('hi');\n", encoding="utf-8")

    # test files
    tests = repo / "tests"
    tests.mkdir()
    (tests / "test_main.py").write_text(
        "def test_dummy():\n    assert True\n",
        encoding="utf-8",
    )

    # config files
    (repo / "pyproject.toml").write_text(
        "[tool]\nname='demo'\n", encoding="utf-8"
    )

    # docs
    (repo / "README.md").write_text(
        "# Demo Repo\nSome text\n", encoding="utf-8"
    )

    return repo


# =============================================================================
# Path & validation tests
# =============================================================================

def test_ensure_path_exists_raises(tmp_path: Path):
    missing = tmp_path / "missing"
    with pytest.raises(InvalidRepositoryError):
        ensure_path_exists(missing)


def test_ensure_is_directory_raises(tmp_path: Path):
    file = tmp_path / "file.txt"
    file.write_text("x", encoding="utf-8")
    with pytest.raises(InvalidRepositoryError):
        ensure_is_directory(file)


def test_validate_repository_root_ok(temp_repo: Path):
    validate_repository_root(temp_repo)


# =============================================================================
# File reading & binary detection
# =============================================================================

def test_safe_read_text_reads_file(temp_repo: Path):
    content = safe_read_text(temp_repo / "main.py")
    assert "print" in content


def test_safe_read_text_binary_returns_empty(tmp_path: Path):
    binary = tmp_path / "bin.dat"
    binary.write_bytes(b"\x00\x01\x02")
    assert safe_read_text(binary) == ""


def test_is_binary_file(tmp_path: Path):
    binary = tmp_path / "bin.dat"
    binary.write_bytes(b"\x00\x00\x00")
    assert is_binary_file(binary) is True


# =============================================================================
# Hashing & size
# =============================================================================

def test_compute_file_hash_matches_sha256(tmp_path: Path):
    file = tmp_path / "data.txt"
    file.write_text("abc", encoding="utf-8")

    expected = hashlib.sha256(b"abc").hexdigest()
    assert compute_file_hash(file) == expected


def test_get_file_size_bytes(tmp_path: Path):
    file = tmp_path / "data.txt"
    file.write_text("abcd", encoding="utf-8")
    assert get_file_size_bytes(file) == 4


def test_get_directory_size_bytes(temp_repo: Path):
    size = get_directory_size_bytes(temp_repo)
    assert size > 0


# =============================================================================
# Language & classification
# =============================================================================

def test_detect_language_from_extension():
    assert detect_language_from_extension(Path("x.py")) == "python"
    assert detect_language_from_extension(Path("x.unknown")) is None


def test_is_test_file_detection():
    assert is_test_file(Path("tests/test_main.py")) is True
    assert is_test_file(Path("main.py")) is False


def test_is_config_file():
    assert is_config_file(Path("pyproject.toml")) is True
    assert is_config_file(Path("random.txt")) is False


def test_is_documentation_file():
    assert is_documentation_file(Path("README.md")) is True
    assert is_documentation_file(Path("main.py")) is False


def test_classify_file(temp_repo: Path):
    assert classify_file(temp_repo / "main.py") == "source"
    assert classify_file(temp_repo / "README.md") == "docs"
    assert classify_file(temp_repo / "pyproject.toml") == "config"


# =============================================================================
# Aggregation & statistics
# =============================================================================

def test_aggregate_language_stats(temp_repo: Path):
    stats = aggregate_language_stats(temp_repo)
    assert stats["python"] >= 1
    assert stats["javascript"] >= 1


def test_aggregate_file_categories(temp_repo: Path):
    cats = aggregate_file_categories(temp_repo)
    assert cats["source"] >= 1
    assert cats["test"] >= 1
    assert cats["docs"] >= 1


# =============================================================================
# Line counting
# =============================================================================

def test_count_lines_in_text():
    text = "a\n\nb\n"
    total, blank, non_blank = count_lines_in_text(text)
    assert total == 3
    assert blank == 1
    assert non_blank == 2


def test_count_lines_in_file(temp_repo: Path):
    file = temp_repo / "main.py"
    total, blank, non_blank = count_lines_in_file(file)
    assert total > 0
    assert non_blank > 0


def test_count_repository_lines(temp_repo: Path):
    result = count_repository_lines(temp_repo)
    assert result["files_counted"] > 0
    assert result["total_lines"] > 0


# =============================================================================
# Ignore rules
# =============================================================================

def test_ignore_rules_basic():
    rules = IgnoreRules()
    rules.add_rule("node_modules")
    rules.add_rule("*.log")

    assert rules.should_ignore(Path("node_modules/x.js"))
    assert rules.should_ignore(Path("error.log"))
    assert not rules.should_ignore(Path("main.py"))


# =============================================================================
# Retry & guard
# =============================================================================

def test_retry_succeeds_after_failure():
    state = {"count": 0}

    def flaky():
        state["count"] += 1
        if state["count"] < 2:
            raise ValueError("fail")
        return "ok"

    result = retry(flaky, attempts=3)
    assert result == "ok"


def test_guard_raises():
    with pytest.raises(RepositoryUtilsError):
        guard(False, "failed guard")


# =============================================================================
# Timer & cache
# =============================================================================

def test_timer_records_elapsed():
    with Timer("test") as t:
        time.sleep(0.01)
    assert t.elapsed > 0


def test_simple_cache_set_get():
    cache = SimpleCache()
    cache.set("a", 123)
    assert cache.get("a") == 123


def test_simple_cache_ttl_expiry():
    cache = SimpleCache()
    cache.set("a", 123, ttl_seconds=0.01)
    time.sleep(0.02)
    assert cache.get("a") is None


# =============================================================================
# Summary builders
# =============================================================================

def test_build_repository_summary(temp_repo: Path):
    summary = build_repository_summary(temp_repo)
    assert "languages" in summary
    assert "file_categories" in summary
    assert "line_counts" in summary


def test_build_extended_repository_summary(temp_repo: Path):
    summary = build_extended_repository_summary(
        temp_repo,
        include_hashes=True,
        include_progress=False,
    )
    assert "files" in summary
    assert isinstance(summary["files"], list)


def test_summarize_repository_quick(temp_repo: Path):
    summary = summarize_repository_quick(temp_repo)
    assert "language_stats" in summary
    assert "file_categories" in summary
