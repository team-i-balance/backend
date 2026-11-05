"""Public metadata only: no source values, filenames, file bytes, or mappings."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from app.schemas import Grade


class FileSummary(BaseModel):
    changed_cells: int
    removed_comments: int
    removed_sheets: int
    removed_rows: int
    removed_columns: int


class FileResult(BaseModel):
    work_id: str
    status: Literal["READY", "BLOCKED", "FAILED"]
    grade: Grade | None = None
    reason: str | None = None
    summary: FileSummary | None = None
    expires_at: datetime | None = None
