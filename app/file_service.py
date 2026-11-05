"""One file processing job, with explicit ownership across worker cancellation."""
from dataclasses import asdict
import threading
from uuid import uuid4

from app import file_events
from app.detectors import get_detector
from app.file_events import FileEvent
from app.file_schemas import FileResult, FileSummary
from app.file_store import FileStoreFull, FileWorkStore
from app.grading import decide_grade
from app.schemas import Action, Grade
from file_sanitizer import LocalPIIProcessor, sanitize_xlsx
from file_sanitizer.local_pii import Findings
from local_ai.pipeline import LocalSession

_GRADES = {"O": Grade.public, "S": Grade.sensitive, "C": Grade.confidential}
_STATUS_CODES = {
    "FILE_TOO_LARGE": 413,
    "UNSUPPORTED_FILE_TYPE": 415,
    "INVALID_INPUT": 422,
    "INVALID_XLSX": 422,
    "UNSUPPORTED_FEATURE": 422,
    "RESIDUAL_CHECK_FAILED": 422,
}


def classify_file_types(detected_types):
    grade = decide_grade(detected_types)
    # Keep future, unrecognized PII types sensitive rather than passing them
    # through as public. The shared policy determines the confidential types.
    if grade == Grade.confidential:
        return "C"
    return "S" if detected_types else "O"


def detection_fields(findings: Findings, *, blocked: bool) -> dict:
    """FileResult's type and count fields (#30): no values, positions or names."""
    return dict(
        detected_types=findings.types,
        detected_count=findings.count,
        detected_counts=dict(sorted(findings.cells.items())),
        hidden_counts=dict(sorted(findings.removed.items())),
        blocked_types=sorted(findings.blocked) if blocked else None,
    )


class FileProcessingJob:
    def __init__(self, store: FileWorkStore, slot: threading.BoundedSemaphore):
        self.work_id = uuid4().hex
        self._store = store
        self._slot = slot  # Already acquired by the router, before reading bytes.
        self._lock = threading.Lock()
        self._started = False
        self._cancelled = False
        self._released = False
        self._stored = False

    def failure(self, code, reason):
        return code, FileResult(work_id=self.work_id, status="FAILED", reason=reason)

    def _release_locked(self):
        if not self._released:
            self._slot.release()
            self._released = True

    def cancel(self):
        with self._lock:
            self._cancelled = True
            if self._stored:
                self._store.discard(self.work_id)
                self._stored = False
            # A cancelled await does not stop a Python worker. Keep its slot
            # until run actually finishes, but release if it never started.
            if not self._started:
                self._release_locked()

    def run(self, data: bytes, filename: str):
        with self._lock:
            if self._cancelled:
                return self.failure(500, "PROCESSING_CANCELLED")
            self._started = True

        session = None
        try:
            try:
                detector = get_detector(False)
                if not detector.model_enabled:
                    return self.failure(503, "MODEL_UNAVAILABLE")
            except Exception:
                return self.failure(503, "MODEL_UNAVAILABLE")

            session = LocalSession(detector)
            processor = LocalPIIProcessor(session, classify=classify_file_types)
            result = sanitize_xlsx(data, self.work_id, processor, filename=filename)
            if result.status == "FAILED":
                return self.failure(_STATUS_CODES.get(result.reason, 500), result.reason)
            blocked = result.status == "BLOCKED"
            detection = detection_fields(processor.findings, blocked=blocked)
            event = FileEvent.of(
                work_id=self.work_id, grade=_GRADES[result.grade],
                findings=processor.findings, data=data,
                model_enabled=detector.model_enabled,
            )
            if blocked:
                # Like /process/decide, answer only once the event is stored (#32).
                try:
                    file_events.record(event, Action.cancel)
                except Exception:
                    return self.failure(500, "EVENT_LOG_FAILED")
                return 200, FileResult(
                    work_id=self.work_id, status="BLOCKED",
                    grade=Grade.confidential, reason=result.reason, **detection,
                )

            summary = FileSummary(**asdict(result.summary))
            with self._lock:
                if self._cancelled:
                    return self.failure(500, "PROCESSING_CANCELLED")
                try:
                    item = self._store.add(
                        work_id=self.work_id, file_bytes=result.file_bytes,
                        session=session, grade=event.grade, summary=summary, event=event,
                    )
                except FileStoreFull:
                    return self.failure(503, "FILE_STORE_FULL")
                self._stored = True
                session = None  # The store now owns the live mapping.
                return 200, FileResult(
                    work_id=item.work_id, status="READY", grade=item.grade,
                    summary=summary, expires_at=item.expires_at, **detection,
                )
        except Exception:
            self.cancel()
            return self.failure(500, "PROCESSING_ERROR")
        finally:
            try:
                if session is not None:
                    session.close()
            finally:
                with self._lock:
                    self._release_locked()
