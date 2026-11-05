"""Security console case review endpoints.

The whole router is mounted behind `require_security` in main.py (issue #45).
"""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from app import case_crud
from app.auth import security_principal
from app.case_schemas import (
    CaseBulkCloseIn, CaseBulkResult, CaseCloseIn, CaseDetail, CaseId, CasePage, CaseQueue,
)


def get_reviewer(principal: Annotated[str, Depends(security_principal)]) -> str:
    """The verified security-team principal (token label, never the raw token).

    Never trust a client-sent name (body or header) for the audit trail.
    """
    return principal


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


router = APIRouter(prefix="/cases", tags=["cases"], dependencies=[Depends(_no_store)])
Reviewer = Annotated[str, Depends(get_reviewer)]


def _call(operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except case_crud.CaseError as exc:
        raise HTTPException(
            status_code=exc.status_code, detail=exc.detail,
            headers={"Cache-Control": "no-store"},
        ) from exc


@router.get("", response_model=CasePage)
def list_cases(
    queue: CaseQueue = "required",
    cursor: Annotated[str | None, Query(max_length=32)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
):
    return _call(case_crud.list_cases, queue=queue, cursor=cursor, limit=limit)


@router.post("/close-bulk", response_model=CaseBulkResult)
def close_bulk(body: CaseBulkCloseIn, reviewer: Reviewer):
    return _call(
        case_crud.close_bulk, body.ids, reviewer=reviewer,
        decision=CaseCloseIn(conclusion=body.conclusion, memo=body.memo),
    )


@router.get("/{case_id}", response_model=CaseDetail)
def get_case(case_id: CaseId):
    return _call(case_crud.get_case, case_id)


@router.post("/{case_id}/close", response_model=CaseDetail)
def close_case(case_id: CaseId, body: CaseCloseIn, reviewer: Reviewer):
    return _call(case_crud.transition, case_id, reviewer=reviewer, decision=body)


@router.post("/{case_id}/reopen", response_model=CaseDetail)
def reopen_case(case_id: CaseId, reviewer: Reviewer):
    return _call(case_crud.transition, case_id, reviewer=reviewer, decision=None)
