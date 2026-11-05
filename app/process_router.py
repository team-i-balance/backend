"""/process, /process/decide, /process/restore.

Runs local_ai on the in-house server, then logs the user's decision.

Flow:
  POST /process {text}  -> server runs local_ai (detect + pseudonymize) and
                           grades the result; returns masked text + metadata
                           and a work_id. Raw text stays in memory only.
  POST /process/decide {work_id, action, reason?}
                        -> builds a log event from the stored metadata + the
                           user's choice and persists it (with queue
                           classification). Returns the text to send onward.
                           For send_transformed the work item is kept alive so
                           the AI reply can be de-pseudonymized later.
  POST /process/restore {work_id, text}
                        -> restore this session's pseudonyms in an AI reply,
                           then release the work item.

Detector reuse: constructing a local_ai Detector builds a tokenizer and ONNX
session, which is expensive and memory-heavy. We build each mode's detector
once and share it across requests; only the per-work pseudonym state lives in
the LocalSession.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app import crud
from app.detectors import (
    MODEL_DIR_ENV,
    SLM_DIR_ENV,
    MissingModelConfiguration,
    get_detector,
    reset_detectors as _reset_detectors,
)
from app.grading import decide_grade
from app.ingest import build_event, coverage_to_confidence
from app.schemas import (
    Action,
    Confidence,
    DecideIn,
    DecideOut,
    Grade,
    ProcessIn,
    ProcessOut,
    RestoreIn,
    RestoreOut,
)
from app.sessions import store

router = APIRouter(prefix="/process", tags=["process"])


def _get_detector(rules_only: bool):
    """Keep the existing text API's configuration error contract."""
    try:
        return get_detector(rules_only)
    except MissingModelConfiguration:
        raise HTTPException(
            status_code=400,
            detail=(
                f"full detection requires {MODEL_DIR_ENV} or {SLM_DIR_ENV} to be set "
                "on the server; use rules_only=true otherwise"
            ),
        ) from None


@router.post("", response_model=ProcessOut)
def process_text(body: ProcessIn):
    from local_ai.pipeline import LocalSession

    detector = _get_detector(body.rules_only)
    # The pseudonym mapping is per-work; the detector is shared.
    session = LocalSession(detector)
    try:
        result = session.process(body.text)
    except Exception:
        # Never leak request text via exception detail.
        session.close()
        raise HTTPException(
            status_code=422,
            detail="detection failed; text was not fully checked",
        )

    grade = decide_grade(result.detection_types)
    confidence = coverage_to_confidence(result.coverage)

    item = store.add(
        session=session,
        original_text=body.text,
        masked_text=result.text,
        detected_types=tuple(result.detection_types),
        detected_count=result.detection_count,  # span count, not distinct types
        grade=grade.value,
        detection_confidence=confidence.value,
        remaining_count=len(result.remaining),
    )

    return ProcessOut(
        work_id=item.work_id,
        masked_text=result.text,
        detected_types=sorted(set(result.detection_types)),
        detected_count=result.detection_count,
        grade=grade.value,
        detection_confidence=confidence.value,
        remaining_count=len(result.remaining),
    )


@router.post("/decide", response_model=DecideOut)
def decide(body: DecideIn):
    item = store.pop(body.work_id)
    if item is None:
        raise HTTPException(status_code=404, detail="unknown or expired work_id")

    keep_session = body.action == Action.send_transformed
    try:
        event_in = build_event(
            work_id=item.work_id,
            original_text=item.original_text,
            detected_types=item.detected_types,
            detected_count=item.detected_count,
            grade=Grade(item.grade),
            detection_confidence=Confidence(item.detection_confidence),
            action=body.action,
            reason=body.reason,
        )
        saved = crud.insert_event(event_in)

        # Decide what the client should actually send onward.
        if body.action == Action.send_transformed:
            outgoing = item.masked_text
        elif body.action in (Action.send_as_is, Action.revert_original):
            outgoing = item.original_text
        else:  # cancel
            outgoing = None
    except Exception:
        # On failure, do not leak the item; release it.
        item.session.close()
        raise

    if keep_session:
        # Re-insert so /process/restore can de-pseudonymize the AI reply.
        store.put(item)
    else:
        item.session.close()

    return DecideOut(
        event=saved, outgoing_text=outgoing, restore_available=keep_session
    )


@router.post("/restore", response_model=RestoreOut)
def restore(body: RestoreIn):
    item = store.pop(body.work_id)
    if item is None:
        raise HTTPException(
            status_code=404,
            detail="unknown or expired work_id (did you call /decide with send_transformed?)",
        )
    try:
        result = item.session.restore(body.text)
        return RestoreOut(
            text=result.text,
            unknown=list(result.unknown),
            blocked=list(result.blocked),
        )
    finally:
        # Restoration is the final step for this work item.
        item.session.close()
