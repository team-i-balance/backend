"""/process and /decide: run local_ai on the in-house server, then log.

Flow:
  POST /process {text}  -> server runs local_ai (detect + pseudonymize) and
                           grades the result; returns masked text + metadata
                           and a work_id. Raw text stays in memory only.
  POST /decide {work_id, action, reason?}
                        -> builds a log event from the stored metadata + the
                           user's choice, persists it (with queue classification)
                           and returns the text to actually send onward.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException

from app import crud
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
)
from app.sessions import store

# Optional local model directory. If unset, only rules_only mode is available.
MODEL_DIR_ENV = "LOCAL_PII_MODEL_DIR"

router = APIRouter(prefix="/process", tags=["process"])


def _build_detector(rules_only: bool):
    # Imported lazily so the logging module works even if local_ai's optional
    # model dependencies are absent.
    from local_ai.detector import Detector

    if rules_only:
        return Detector(None)
    model_dir = os.getenv(MODEL_DIR_ENV)
    if not model_dir:
        raise HTTPException(
            status_code=400,
            detail=(
                f"full detection requires {MODEL_DIR_ENV} to be set on the "
                "server; use rules_only=true otherwise"
            ),
        )
    return Detector(model_dir)


@router.post("", response_model=ProcessOut)
def process_text(body: ProcessIn):
    from local_ai.pipeline import LocalSession

    detector = _build_detector(body.rules_only)
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
        detected_count=len(result.detection_types),
        grade=grade.value,
        detection_confidence=confidence.value,
        remaining_count=len(result.remaining),
    )

    return ProcessOut(
        work_id=item.work_id,
        masked_text=result.text,
        detected_types=sorted(set(result.detection_types)),
        detected_count=len(result.detection_types),
        grade=grade.value,
        detection_confidence=confidence.value,
        remaining_count=len(result.remaining),
    )


@router.post("/decide", response_model=DecideOut)
def decide(body: DecideIn):
    item = store.pop(body.work_id)
    if item is None:
        raise HTTPException(status_code=404, detail="unknown or expired work_id")

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

        return DecideOut(event=saved, outgoing_text=outgoing)
    finally:
        # Always release the local_ai session for this work item.
        item.session.close()
