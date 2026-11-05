"""/policy endpoints (S7).

PC side:
  POST /policy/deploy          verify a DSSE bundle; apply if valid + newer
  GET  /policy/current         active policy metadata

Backend (console) side:
  POST /policy/publish         sign a payload into a bundle, version+1, store
  GET  /policy/latest          latest bundle (ETag = bundle sha256; 304 aware)
  GET  /policy/{version}       a specific bundle (audit / replay)
  POST /policy/ack             record a PC agent's apply/reject result
  GET  /policy/acks            aggregate apply/reject counts

Model manifest:
  POST /policy/model/publish   sign + store a model manifest
  GET  /policy/model/latest    latest signed model manifest
"""
from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, Response

from app.policy import (
    ActivePolicy,
    DEMO_KEY_ID,
    make_model_bundle,
    store,
)
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
@router.post("/deploy", response_model=DeployOut)
def deploy(body: DeployIn):
    accepted, reason = store.deploy(body.bundle)
    return DeployOut(accepted=accepted, reason=reason, policy=_info(store.current()))


@router.get("/current", response_model=PolicyInfo)
def current():
    return _info(store.current())


# --- Backend / console side -------------------------------------------------
@router.post("/publish", response_model=PublishOut)
def publish(body: PublishIn):
    stored = store.publish(body.payload)
    return PublishOut(
        version=stored.version, keyid=DEMO_KEY_ID, bundle_sha256=stored.sha256
    )


@router.get("/latest")
def latest(response: Response, if_none_match: str | None = Header(default=None)):
    stored = store.latest()
    if stored is None:
        raise HTTPException(status_code=404, detail="no policy published yet")
    # ETag = bundle sha256. If the client already has it, return 304.
    if if_none_match is not None and if_none_match == stored.sha256:
        return Response(status_code=304, headers={"ETag": stored.sha256})
    response.headers["ETag"] = stored.sha256
    return stored.envelope


@router.get("/acks", response_model=AckOut)
def acks():
    return AckOut(ok=True, summary=store.ack_summary())


@router.post("/ack", response_model=AckOut)
def ack(body: AckIn):
    store.record_ack(body.device_id, body.version, body.status.value, body.reason)
    return AckOut(ok=True, summary=store.ack_summary())


# --- model manifest ---------------------------------------------------------
@router.post("/model/publish")
def model_publish(body: ModelPublishIn):
    manifest = {
        "name": body.name,
        "version": body.version,
        "sha256": body.sha256,
        "url": body.url,
    }
    bundle = make_model_bundle(manifest)
    store.set_model_manifest(bundle)
    return {"published": True, "name": body.name, "version": body.version}


@router.get("/model/latest")
def model_latest():
    manifest = store.model_manifest()
    if manifest is None:
        raise HTTPException(status_code=404, detail="no model manifest published")
    return manifest


# --- audit: specific version (declared last so it doesn't shadow the others) -
@router.get("/{version}")
def get_version(version: int):
    stored = store.get_version(version)
    if stored is None:
        raise HTTPException(status_code=404, detail="unknown version")
    return stored.envelope
