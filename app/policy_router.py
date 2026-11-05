"""/policy: deploy a signed policy bundle and read the active policy (S7).

Deploy verifies the bundle's signature. If valid and newer, it becomes the
active policy; otherwise the request is rejected and the previous policy is
kept. Applying the policy to actual transformation is a later step.
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
        key_id=active.key_id,
        rule_count=active.rule_count,
        activated_at=active.activated_at,
    )


@router.post("/deploy", response_model=DeployOut)
def deploy(body: DeployIn):
    accepted, reason = store.deploy(body.bundle)
    return DeployOut(accepted=accepted, reason=reason, policy=_info(store.current()))


@router.get("/current", response_model=PolicyInfo)
def current():
    return _info(store.current())
