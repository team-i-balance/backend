"""/policy endpoints (S7).

PC side:
  POST /policy/deploy          verify a DSSE bundle; apply if valid + newer
  GET  /policy/current         active policy metadata

Backend (console) side:
  POST /policy/publish         sign a payload into a bundle, version+1, store
  GET  /policy/draft           saved draft or latest published payload + ETag
  PUT  /policy/draft           save a full draft with If-Match concurrency control
  GET  /policy/latest          latest bundle (ETag = bundle sha256; 304 aware)
  GET  /policy/history         published bundles, newest first
  GET  /policy/{version}       a specific bundle (audit / replay)
  POST /policy/ack             record a PC agent's apply/reject result
  GET  /policy/acks            aggregate apply/reject counts (?version=N)
  GET  /policy/{version}/acks  counts for one version

Model manifest:
  POST /policy/model/publish   sign + store a model manifest
  GET  /policy/model/latest    latest signed model manifest
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from pydantic import BaseModel

from app.auth import require_api, require_security
from app.policy import (
    ActivePolicy,
    DEMO_KEY_ID,
    SigningKeyError,
    store,
)
from app.policy_draft import DraftError
from app.policy_draft_schemas import DraftIn, DraftOut
from app.schemas import (
    AckIn,
    AckOut,
    DeployIn,
    DeployOut,
    ModelPublishIn,
    PolicyInfo,
    PublishIn,
    PublishOut,
)

router = APIRouter(prefix="/policy", tags=["policy"])


class HistoryItem(BaseModel):
    """One published bundle. stored_at is the server's UTC ISO store time;
    null if the bundle was stored without one (never invented)."""

    version: int
    sha256: str
    stored_at: Optional[str] = None
    rule_count: int


class VersionAcks(BaseModel):
    """Apply/reject counts for one version (each device's last ack for it)."""

    version: int
    devices: int
    applied: int
    rejected: int
    reject_reasons: dict[str, int]


def _info(active: ActivePolicy | None) -> PolicyInfo:
    if active is None:
        return PolicyInfo(active=False)
    return PolicyInfo(
        active=True,
        version=active.version,
        org=active.org,
        key_id=active.keyid,
        rule_count=active.rule_count,
        activated_at=active.activated_at,
        expires_at=active.expires_at,
    )


# --- PC side ----------------------------------------------------------------
@router.post("/deploy", response_model=DeployOut, dependencies=[Depends(require_api)])
def deploy(body: DeployIn):
    accepted, reason = store.deploy(body.bundle)
    return DeployOut(accepted=accepted, reason=reason, policy=_info(store.current()))


@router.get("/current", response_model=PolicyInfo, dependencies=[Depends(require_api)])
def current():
    return _info(store.current())


# --- Backend / console side -------------------------------------------------
def get_policy_editor() -> str:
    """Replace with the verified security-team account when authentication (#10) lands."""
    return "unauthenticated"


def _draft_error(exc: DraftError) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code, detail=exc.detail, headers={"Cache-Control": "no-store"},
    )


@router.get("/draft", response_model=DraftOut, dependencies=[Depends(require_security)])
def get_draft(response: Response):
    state = store.draft()
    response.headers["ETag"] = state["etag"]
    response.headers["Cache-Control"] = "no-store"
    return state


@router.put("/draft", response_model=DraftOut, dependencies=[Depends(require_security)])
def put_draft(
    body: DraftIn,
    response: Response,
    if_match: Optional[str] = Header(default=None, max_length=128),
    editor: str = Depends(get_policy_editor),
):
    try:
        state = store.save_draft(
            body.payload, [change.model_dump() for change in body.changes],
            if_match=if_match, editor=editor,
        )
    except DraftError as exc:
        raise _draft_error(exc) from exc
    response.headers["ETag"] = state["etag"]
    response.headers["Cache-Control"] = "no-store"
    return state


@router.post("/publish", response_model=PublishOut, dependencies=[Depends(require_security)])
def publish(
    response: Response,
    body: Optional[PublishIn] = None,
    if_match: Optional[str] = Header(default=None, max_length=128),
):
    try:
        stored = store.publish(body.payload if body else None, if_match=if_match)
    except DraftError as exc:
        raise _draft_error(exc) from exc
    except SigningKeyError as exc:
        raise HTTPException(
            status_code=503, detail="policy signing key unavailable; restore the original key files",
        ) from exc
    response.headers["Cache-Control"] = "no-store"
    return PublishOut(
        version=stored.version, keyid=DEMO_KEY_ID, bundle_sha256=stored.sha256
    )


@router.get("/latest", dependencies=[Depends(require_api)])
def latest(response: Response, if_none_match: str | None = Header(default=None)):
    stored = store.latest()
    if stored is None:
        raise HTTPException(status_code=404, detail="no policy published yet")
    # ETag = bundle sha256. If the client already has it, return 304.
    if if_none_match is not None and if_none_match == stored.sha256:
        return Response(status_code=304, headers={"ETag": stored.sha256})
    response.headers["ETag"] = stored.sha256
    return stored.envelope


@router.get("/acks", response_model=AckOut, dependencies=[Depends(require_security)])
def acks(version: Optional[int] = Query(default=None)):
    # Without ?version: each device's last ack (legacy console view).
    # With ?version=N: only acks for N. Response shape is the same either way.
    return AckOut(ok=True, summary=store.ack_summary(version))


@router.get("/history", response_model=list[HistoryItem], dependencies=[Depends(require_security)])
def history():
    return [
        HistoryItem(
            version=s.version,
            sha256=s.sha256,
            stored_at=s.stored_at,
            rule_count=s.rule_count,
        )
        for s in store.history()
    ]


@router.get("/{version}/acks", response_model=VersionAcks, dependencies=[Depends(require_security)])
def version_acks(version: int):
    if store.get_version(version) is None and not store.has_acks(version):
        raise HTTPException(status_code=404, detail="unknown version")
    return VersionAcks(version=version, **store.ack_summary(version))


@router.post("/ack", response_model=AckOut, dependencies=[Depends(require_api)])
def ack(body: AckIn):
    store.record_ack(body.device_id, body.version, body.status.value, body.reason)
    return AckOut(ok=True, summary=store.ack_summary())


# --- model manifest ---------------------------------------------------------
@router.post("/model/publish", dependencies=[Depends(require_security)])
def model_publish(body: ModelPublishIn):
    manifest = {
        "name": body.name,
        "version": body.version,
        "sha256": body.sha256,
        "url": body.url,
    }
    try:
        store.publish_model(manifest)
    except SigningKeyError as exc:
        raise HTTPException(
            status_code=503, detail="policy signing key unavailable; restore the original key files",
        ) from exc
    return {"published": True, "name": body.name, "version": body.version}


@router.get("/model/latest", dependencies=[Depends(require_api)])
def model_latest():
    manifest = store.model_manifest()
    if manifest is None:
        raise HTTPException(status_code=404, detail="no model manifest published")
    return manifest


# --- audit: specific version (declared last so it doesn't shadow the others) -
@router.get("/{version}", dependencies=[Depends(require_api)])
def get_version(version: int):
    stored = store.get_version(version)
    if stored is None:
        raise HTTPException(status_code=404, detail="unknown version")
    return stored.envelope
