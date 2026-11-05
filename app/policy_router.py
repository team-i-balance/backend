"""/policy: deploy a signed DSSE policy bundle and read the active policy (S7).

Deploy verifies the bundle per the team spec (DSSE envelope + Ed25519 over PAE
bytes + the 7 ordered checks). If it passes and is newer, it becomes the active
policy; otherwise the request is rejected with the spec reason code and the
previous policy is kept. Applying rules to the SLM and /publish, /ack, and the
model manifest are later steps.
"""
from __future__ import annotations

from fastapi import APIRouter

from app.policy import ActivePolicy, store
from app.schemas import DeployIn, DeployOut, PolicyInfo

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


@router.post("/deploy", response_model=DeployOut)
def deploy(body: DeployIn):
    accepted, reason = store.deploy(body.bundle)
    return DeployOut(accepted=accepted, reason=reason, policy=_info(store.current()))


@router.get("/current", response_model=PolicyInfo)
def current():
    return _info(store.current())
