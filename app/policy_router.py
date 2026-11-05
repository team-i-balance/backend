"""/policy endpoints (S7).

Server detection (security token):
  POST /policy/deploy          verify + compile a DSSE bundle; activate if valid + newer

Read (api token; the employee program uses it as its token check):
  GET  /policy/current         active policy metadata, the version detection actually
                               uses, the last apply error code, hmac key presence

Backend (console) side:
  POST /policy/publish         sign a payload into a bundle, version+1, store
  GET  /policy/draft           saved draft or latest published payload + ETag
  PUT  /policy/draft           save a full draft with If-Match concurrency control
  GET  /policy/latest          latest bundle (ETag = "bundle sha256"; 304 aware)
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

import os
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from pydantic import BaseModel

from app.auth import require_api, require_security, security_principal
from app.etag import if_none_match_hits, quote_etag
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
    null if the bundle was stored without one (never invented). published_by is the
    security principal that published it; null for bundles stored before #59."""

    version: int
    sha256: str
    stored_at: Optional[str] = None
    rule_count: int
    published_by: Optional[str] = None


class ApplyError(BaseModel):
    """Most recent failure to apply a policy on this server process (code only)."""

    version: Optional[int] = None
    code: str
    at: str


class PolicyCurrent(PolicyInfo):
    """PolicyInfo plus what detection actually runs with (#64) and config checks (#65)."""

    activated_by: Optional[str] = None
    # Version requests detect with. Differs from ``version`` when the active policy
    # failed to apply and the previous one stays in effect (null: no policy in effect).
    effective_version: Optional[int] = None
    last_apply_error: Optional[ApplyError] = None
    # POLICY_VALUE_HASH_KEY is set: "hmac:" dict/exclude entries apply (else skipped).
    value_hash_key_set: bool = False


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


# --- Backend / console side -------------------------------------------------
def get_policy_editor(principal: str = Depends(security_principal)) -> str:
    """Who changes policy: the verified security principal, as in case history (#59)."""
    return principal


# --- server detection --------------------------------------------------------
@router.post("/deploy", response_model=DeployOut, dependencies=[Depends(require_security)])
def deploy(body: DeployIn, editor: str = Depends(get_policy_editor)):
    # Security only (#65): activating changes what the server detects for everyone.
    accepted, reason = store.deploy(body.bundle, by=editor)
    return DeployOut(accepted=accepted, reason=reason, policy=_info(store.current()))


@router.get("/current", response_model=PolicyCurrent, dependencies=[Depends(require_api)])
def current():
    from app.policy_apply import VALUE_HASH_KEY_ENV, runtime_status

    active = store.current()
    return PolicyCurrent(
        **_info(active).model_dump(),
        activated_by=active.activated_by if active else None,
        **runtime_status(active),
        value_hash_key_set=bool(os.getenv(VALUE_HASH_KEY_ENV)),
    )


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
            if_match=if_match, editor=editor, console_state=body.console_state,
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
    editor: str = Depends(get_policy_editor),
):
    try:
        stored = store.publish(body.payload if body else None, if_match=if_match, by=editor)
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
    # ETag = quoted bundle sha256 ("sha256:<hex>"). If the client already has
    # it (quoted or legacy unquoted, W/, list, or *), return 304.
    etag = quote_etag(stored.sha256)
    if if_none_match_hits(if_none_match, stored.sha256):
        return Response(status_code=304, headers={"ETag": etag})
    response.headers["ETag"] = etag
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
            published_by=s.published_by,
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
