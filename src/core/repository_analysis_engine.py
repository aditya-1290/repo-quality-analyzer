"""
Repository Analysis Engine

This module implements a monolithic, enterprise-style analysis engine
used to coordinate repository inspection, validation, execution flow,
error handling, progress tracking, and structured reporting.

The implementation favors clarity, defensive programming, explicit
state handling, and extensibility over minimalism.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime


# =============================================================================
# Logging
# =============================================================================

LOGGER_NAME = "repo_quality.engine"
logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(logging.INFO)


# =============================================================================
# Enumerations
# =============================================================================

class AnalysisState(Enum):
    CREATED = "created"
    INITIALIZED = "initialized"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class SeverityLevel(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OutputFormat(Enum):
    JSON = "json"
    TEXT = "text"


class EnginePhase(Enum):
    PRE_CHECKS = "pre_checks"
    STRUCTURE_SCAN = "structure_scan"
    METRIC_COLLECTION = "metric_collection"
    FINALIZATION = "finalization"


class EngineErrorCategory(Enum):
    CONFIGURATION = "configuration"
    IO = "io"
    TIMEOUT = "timeout"
    INTERNAL = "internal"


class EngineHook(Enum):
    BEFORE_ANALYSIS = "before_analysis"
    AFTER_ANALYSIS = "after_analysis"
    ON_FAILURE = "on_failure"


# =============================================================================
# Configuration & Models
# =============================================================================

@dataclass
class EngineConfiguration:
    max_files: int = 100_000
    max_runtime_seconds: int = 600
    enable_logging: bool = True
    include_details: bool = True
    fail_fast: bool = False
    output_format: OutputFormat = OutputFormat.JSON

    def validate(self) -> List[str]:
        errors: List[str] = []

        if self.max_files <= 0:
            errors.append("max_files must be greater than zero")

        if self.max_runtime_seconds <= 0:
            errors.append("max_runtime_seconds must be greater than zero")

        if not isinstance(self.enable_logging, bool):
            errors.append("enable_logging must be boolean")

        if not isinstance(self.include_details, bool):
            errors.append("include_details must be boolean")

        if not isinstance(self.fail_fast, bool):
            errors.append("fail_fast must be boolean")

        if not isinstance(self.output_format, OutputFormat):
            errors.append("output_format must be OutputFormat enum")

        return errors


@dataclass
class EngineMetadata:
    analysis_id: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    state: AnalysisState = AnalysisState.CREATED


@dataclass
class EngineFinding:
    message: str
    severity: SeverityLevel
    source: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ExecutionContext:
    start_time: float
    last_heartbeat: float
    cancelled: bool = False
    timeout_triggered: bool = False


@dataclass
class EngineResult:
    repository_path: str
    metadata: EngineMetadata
    findings: List[EngineFinding]
    metrics: Dict[str, Any]
    errors: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repository_path": self.repository_path,
            "metadata": {
                "analysis_id": self.metadata.analysis_id,
                "state": self.metadata.state.value,
                "started_at": self.metadata.started_at.isoformat(),
                "finished_at": self.metadata.finished_at.isoformat()
                if self.metadata.finished_at else None,
                "duration_seconds": self.metadata.duration_seconds,
            },
            "findings": [
                {
                    "message": f.message,
                    "severity": f.severity.value,
                    "source": f.source,
                    "timestamp": f.timestamp.isoformat(),
                }
                for f in self.findings
            ],
            "metrics": self.metrics,
            "errors": self.errors,
        }


# =============================================================================
# Core Engine
# =============================================================================

class RepositoryAnalysisEngine:
    """
    Central orchestration engine for repository analysis.

    Responsibilities:
    - Input validation
    - Execution lifecycle management
    - Phase tracking
    - Error handling
    - Progress reporting
    - Hook execution
    """

    def __init__(
        self,
        repository_path: str,
        config: Optional[EngineConfiguration] = None,
    ) -> None:
        self.repository_path = Path(repository_path).resolve()
        self.config = config or EngineConfiguration()

        self.metadata = EngineMetadata(
            analysis_id=self._generate_analysis_id(),
            started_at=datetime.utcnow(),
        )

        self.findings: List[EngineFinding] = []
        self.metrics: Dict[str, Any] = {}
        self.errors: List[str] = []

        self._context = ExecutionContext(
            start_time=time.time(),
            last_heartbeat=time.time(),
        )

        self._phases_executed: List[EnginePhase] = []

        self._hooks: Dict[EngineHook, List[Callable]] = {
            EngineHook.BEFORE_ANALYSIS: [],
            EngineHook.AFTER_ANALYSIS: [],
            EngineHook.ON_FAILURE: [],
        }

        if self.config.enable_logging:
            logger.info("RepositoryAnalysisEngine created")

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def run(self) -> EngineResult:
        try:
            self._run_hooks(EngineHook.BEFORE_ANALYSIS)
            self._initialize()
            self._execute()
            self._finalize(success=True)
            self._run_hooks(EngineHook.AFTER_ANALYSIS)
        except Exception as exc:  # noqa
            self._record_error(str(exc), EngineErrorCategory.INTERNAL)
            self._run_hooks(EngineHook.ON_FAILURE)
            self._finalize(success=False)

        return EngineResult(
            repository_path=str(self.repository_path),
            metadata=self.metadata,
            findings=self.findings,
            metrics=self.metrics,
            errors=self.errors,
        )

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def _initialize(self) -> None:
        self.metadata.state = AnalysisState.INITIALIZED

        config_errors = self.config.validate()
        if config_errors:
            for err in config_errors:
                self.errors.append(err)
            raise ValueError("Invalid engine configuration")

        if not self.repository_path.exists():
            raise FileNotFoundError(
                f"Repository path does not exist: {self.repository_path}"
            )

        if not self.repository_path.is_dir():
            raise ValueError("Repository path must be a directory")

        logger.info("Initialization completed")

    def _execute(self) -> None:
        self.metadata.state = AnalysisState.RUNNING
        start = time.time()

        self._mark_phase(EnginePhase.PRE_CHECKS)
        self._check_repository_size()

        self._mark_phase(EnginePhase.STRUCTURE_SCAN)
        self._scan_structure()

        self._mark_phase(EnginePhase.METRIC_COLLECTION)
        self._collect_basic_metrics()

        self.metadata.duration_seconds = time.time() - start

    def _finalize(self, success: bool) -> None:
        self.metadata.finished_at = datetime.utcnow()
        self.metadata.state = (
            AnalysisState.COMPLETED if success else AnalysisState.PARTIAL
        )

    # -------------------------------------------------------------------------
    # Phase helpers
    # -------------------------------------------------------------------------

    def _mark_phase(self, phase: EnginePhase) -> None:
        self._phases_executed.append(phase)
        self._heartbeat()
        self._check_timeout()
        logger.info("Executed phase: %s", phase.value)

    # -------------------------------------------------------------------------
    # Analysis steps
    # -------------------------------------------------------------------------

    def _check_repository_size(self) -> None:
        file_count = sum(1 for _ in self.repository_path.rglob("*"))
        self.metrics["file_count"] = file_count

        if file_count > self.config.max_files:
            message = (
                f"Repository contains {file_count} files "
                f"(limit: {self.config.max_files})"
            )
            self._add_finding(
                message,
                SeverityLevel.HIGH,
                "size_check",
            )
            if self.config.fail_fast:
                raise RuntimeError(message)

    def _scan_structure(self) -> None:
        directories = set()
        for path in self.repository_path.rglob("*"):
            if path.is_dir():
                directories.add(path.name)

        self.metrics["directories"] = sorted(directories)

        if "tests" not in directories:
            self._add_finding(
                "No tests directory detected",
                SeverityLevel.MEDIUM,
                "structure_scan",
            )

        if ".github" not in directories:
            self._add_finding(
                "No CI configuration detected",
                SeverityLevel.LOW,
                "structure_scan",
            )

    def _collect_basic_metrics(self) -> None:
        extension_map: Dict[str, int] = {}

        for file in self.repository_path.rglob("*"):
            if file.is_file():
                suffix = file.suffix.lower() or "<none>"
                extension_map[suffix] = extension_map.get(suffix, 0) + 1

        self.metrics["file_extensions"] = dict(sorted(extension_map.items()))

    # -------------------------------------------------------------------------
    # Error & finding handling
    # -------------------------------------------------------------------------

    def _add_finding(
        self,
        message: str,
        severity: SeverityLevel,
        source: str,
    ) -> None:
        self.findings.append(
            EngineFinding(
                message=message,
                severity=severity,
                source=source,
            )
        )

    def _record_error(
        self,
        message: str,
        category: EngineErrorCategory,
    ) -> None:
        formatted = f"[{category.value.upper()}] {message}"
        self.errors.append(formatted)
        logger.error(formatted)

    # -------------------------------------------------------------------------
    # Execution context
    # -------------------------------------------------------------------------

    def _heartbeat(self) -> None:
        self._context.last_heartbeat = time.time()

    def _check_timeout(self) -> None:
        elapsed = time.time() - self._context.start_time
        if elapsed > self.config.max_runtime_seconds:
            self._context.timeout_triggered = True
            raise TimeoutError("Analysis exceeded max runtime")

    # -------------------------------------------------------------------------
    # Hooks
    # -------------------------------------------------------------------------

    def register_hook(
        self,
        hook: EngineHook,
        callback: Callable,
    ) -> None:
        self._hooks[hook].append(callback)

    def _run_hooks(self, hook: EngineHook) -> None:
        for callback in self._hooks.get(hook, []):
            try:
                callback(self)
            except Exception as exc:  # noqa
                logger.warning("Hook failed: %s", exc)

    # -------------------------------------------------------------------------
    # Diagnostics & export
    # -------------------------------------------------------------------------

    def get_progress_snapshot(self) -> Dict[str, Any]:
        return {
            "state": self.metadata.state.value,
            "phases": [p.value for p in self._phases_executed],
            "findings": len(self.findings),
            "errors": len(self.errors),
            "elapsed_seconds": round(
                time.time() - self._context.start_time, 2
            ),
        }

    def dump_diagnostics(self) -> Dict[str, Any]:
        return {
            "analysis_id": self.metadata.analysis_id,
            "repository": str(self.repository_path),
            "state": self.metadata.state.value,
            "config": self.config.__dict__,
            "metrics_keys": list(self.metrics.keys()),
            "findings": len(self.findings),
            "errors": self.errors,
        }

    def export(self, result: EngineResult) -> str:
        if self.config.output_format == OutputFormat.JSON:
            return json.dumps(result.to_dict(), indent=2)

        lines: List[str] = []
        lines.append(f"Repository: {result.repository_path}")
        lines.append(f"State: {result.metadata.state.value}")
        lines.append(f"Duration: {result.metadata.duration_seconds}s")
        lines.append("")

        for finding in result.findings:
            lines.append(
                f"[{finding.severity.value.upper()}] "
                f"{finding.source}: {finding.message}"
            )

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Utilities
    # -------------------------------------------------------------------------

    @staticmethod
    def _generate_analysis_id() -> str:
        return f"analysis-{uuid.uuid4().hex}"
