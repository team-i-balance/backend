"""Public metadata only: no source values, filenames, file bytes, or mappings."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

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
    # Types and counts only (issue #30). null when the file was not fully checked (FAILED).
    detected_types: list[str] | None = Field(
        default=None,
        description="Every type found anywhere in the file, as in the text API.",
    )
    detected_count: int | None = Field(
        default=None,
        description="Places found in the whole file: detected_counts plus hidden_counts.",
    )
    detected_counts: dict[str, int] | None = Field(
        default=None,
        description="Places per type in the cells of the protected copy, where they are masked.",
    )
    hidden_counts: dict[str, int] | None = Field(
        default=None,
        description=(
            "Places per type in parts the protected copy leaves out: file name, document "
            "properties, sheet names, comments, hidden sheets/rows/columns."
        ),
    )
    blocked_types: list[str] | None = Field(
        default=None,
        description="BLOCKED only: the types that made the file confidential.",
    )


class FileRestoreIn(BaseModel):
    """An AI reply whose placeholders a file work's mapping should restore."""

    text: str = Field(max_length=200_000)
