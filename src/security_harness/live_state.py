import threading
from dataclasses import dataclass


@dataclass
class WorkerPoolStatus:
    phase: str  # "analysis" | "verify" | "idle"
    active: int
    capacity: int


class LiveState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._analysis_active: set[str] = set()
        self._verify_active: set[int] = set()
        self._analysis_workers = WorkerPoolStatus(phase="idle", active=0, capacity=0)
        self._verify_workers = WorkerPoolStatus(phase="idle", active=0, capacity=0)

    def add_active_file(self, path: str) -> None:
        with self._lock:
            self._analysis_active.add(path)

    def remove_active_file(self, path: str) -> None:
        with self._lock:
            self._analysis_active.discard(path)

    def add_active_verify(self, attempt_id: int) -> None:
        with self._lock:
            self._verify_active.add(attempt_id)

    def remove_active_verify(self, attempt_id: int) -> None:
        with self._lock:
            self._verify_active.discard(attempt_id)

    def set_analysis_workers(self, active: int, capacity: int, phase: str = "analysis") -> None:
        with self._lock:
            self._analysis_workers = WorkerPoolStatus(phase=phase, active=active, capacity=capacity)

    def set_verify_workers(self, active: int, capacity: int, phase: str = "verify") -> None:
        with self._lock:
            self._verify_workers = WorkerPoolStatus(phase=phase, active=active, capacity=capacity)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "analysis_active": sorted(self._analysis_active),
                "verify_active": sorted(self._verify_active),
                "analysis_workers": WorkerPoolStatus(
                    phase=self._analysis_workers.phase,
                    active=self._analysis_workers.active,
                    capacity=self._analysis_workers.capacity,
                ),
                "verify_workers": WorkerPoolStatus(
                    phase=self._verify_workers.phase,
                    active=self._verify_workers.active,
                    capacity=self._verify_workers.capacity,
                ),
            }
