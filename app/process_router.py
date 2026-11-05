"""/process, /process/decide, /process/restore.

Runs local_ai on the in-house server, then logs the user's decision.

Flow:
  POST /process {text}  -> server runs local_ai (detect + pseudonymize) and
                           grades the result; returns masked text + metadata
                           and a work_id. Raw text stays in memory only.
  POST /process/decide {work_id, action, reason?, reason_text?, user_id?,
                        dept?, target_ai?, reverted?}
                        -> builds a log event from the stored metadata + the
                           user's choice, with one item per masked span
                           (type, decision, value HMAC, masked preview; never
                           the value), and persists it (with queue
                           classification). Returns the text to send onward.
                           For send_transformed the work item is kept alive so
                           the AI reply can be de-pseudonymized later.
  POST /process/restore {work_id, text}
                        -> restore this session's pseudonyms in an AI reply,
                           then release the work item.

A question sent with an XLSX file passes that file's work_id as file_work_id.
It is then numbered in the file's mapping (borrowed, never closed here), so the
AI never sees one placeholder for two values and either restore covers both.

Detector reuse: constructing a local_ai Detector builds a tokenizer and ONNX
session, which is expensive and memory-heavy. We build each mode's detector
once and share it across requests; only the per-work pseudonym state lives in
the LocalSession.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response

from app import crud
from app.decide_items import (
    build_items,
    check_reverted,
    partially_restored,
)
from app.detectors import (
    MODEL_DIR_ENV,
    SLM_DIR_ENV,
    MissingModelConfiguration,
    get_detector,
    reset_detectors as _reset_detectors,
)
from app.file_mapping import MappingClosed
from app.file_store import store as file_store
from app.grading import decide_grade
from app.ingest import build_event, coverage_to_confidence
from app.schemas import (
    Action,
    Confidence,
    DecideIn,
    DecideOut,
    Grade,
    PreviewIn,
    PreviewOut,
    PreviewSpan,
    ProcessIn,
    ProcessOut,
    RestoreIn,
    RestoreOut,
)
from app.sessions import store
from local_ai.pseudonym import PlaceholderReuseError

router = APIRouter(prefix="/process", tags=["process"])
_FILE_WORK_GONE = "unknown or expired file_work_id"


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


def _active_detection(rules_only):
    from app.policy import store as policy_store
    from app.policy_apply import apply_policy_to_detector

    detector = _get_detector(rules_only)
    # Read the active policy once and compile it (cached while unchanged). The
    # request detects with that snapshot only, so a concurrent deploy cannot mix
    # policies, and the logged version is the one used (#47, #49). A policy that
    # fails to apply leaves the previous one in effect; ``applied.version`` says which.
    applied = apply_policy_to_detector(detector, policy_store.current())
    return applied.bind(detector), applied


@router.post("/preview", response_model=PreviewOut)
def preview_text(body: PreviewIn, response: Response):
    """Live prompt highlighting. No work item, original value, mapping or event is created."""
    detector, _ = _active_detection(body.rules_only)
    try:
        spans = [PreviewSpan(start=s["start"], end=s["end"], type=s["type"])
                 for s in detector.detect(body.text)]
    except Exception:
        raise HTTPException(status_code=422, detail="draft detection failed") from None
    response.headers["Cache-Control"] = "no-store"
    return PreviewOut(spans=spans)


@router.post("", response_model=ProcessOut)
def process_text(body: ProcessIn):
    from local_ai.pipeline import LocalSession

    detector, applied = _active_detection(body.rules_only)
    if body.file_work_id is None:
        # The pseudonym mapping is per-work; the detector is shared.
        session = LocalSession(detector)
    else:
        session = file_store.lend(body.file_work_id)
        if session is None:
            raise HTTPException(status_code=404, detail=_FILE_WORK_GONE)
    try:
        result = session.process(body.text)
    except MappingClosed:
        raise HTTPException(status_code=404, detail=_FILE_WORK_GONE) from None
    except PlaceholderReuseError:
        # Only a linked question can hit this: a placeholder copied from the
        # protected file cannot be told apart from literal text, so fail closed.
        session.close()
        raise HTTPException(status_code=422, detail=(
            "text contains a placeholder of the linked file; "
            "write the original value instead"
        )) from None
    except Exception:
        # Never leak request text via exception detail.
        session.close()
        raise HTTPException(
            status_code=422,
            detail="detection failed; text was not fully checked",
        )

    grade = decide_grade(result.detection_types, applied.grade_overrides)
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
        # The version this detection used (issues #47, #49).
        policy_version=applied.version,
        spans=tuple(getattr(result, "spans", ())),
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

    reverted = None
    if body.reverted is not None:
        try:
            reverted = check_reverted(item.spans, body.reverted)
        except ValueError as exc:
            # A client mistake must not consume the work: keep it for a retry.
            store.put(item)
            raise HTTPException(status_code=422, detail=str(exc)) from None

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
            user_id=body.user_id,
            dept=body.dept,
            target_ai=body.target_ai,
            reason_text=body.reason_text,
            items=build_items(item.spans, body.action, reverted),
            policy_version=item.policy_version,
        )
        saved = crud.insert_event(event_in)

        # Decide what the client should actually send onward.
        if body.action == Action.send_transformed:
            outgoing = item.masked_text
        elif body.action == Action.revert_original and reverted is not None:
            outgoing = partially_restored(item.masked_text, item.spans, reverted)
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
    except MappingClosed:
        # A question linked to a file work that has since ended.
        raise HTTPException(
            status_code=404, detail="unknown or expired work_id (the linked file work has ended)",
        ) from None
    finally:
        # Restoration is the final step for this work item.
        item.session.close()
    return RestoreOut(
        text=result.text,
        unknown=list(result.unknown),
        blocked=list(result.blocked),
    )
