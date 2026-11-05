"""Draft payloads remain opaque, just like /policy/publish payloads."""
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class DraftChangeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    what: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]
    src: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)] = "직접 수정"
    # Accepted for GET -> edit -> PUT round trips; the server ignores them.
    at: str | None = Field(default=None, max_length=64)
    by: str | None = Field(default=None, max_length=128)


class DraftIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload: dict
    changes: list[DraftChangeIn] = Field(max_length=500)
    # Unsigned console screen state (may contain plaintext). Stored with the
    # draft but never copied into a published payload; null/omitted clears it.
    console_state: dict | None = None


class DraftChangeOut(BaseModel):
    what: str
    src: str
    at: str
    by: str


class DraftOut(BaseModel):
    payload: dict | None
    changes: list[DraftChangeOut]
    console_state: dict | None
    has_draft: bool
    base_version: int | None
    revision: int
    updated_at: str | None
    updated_by: str | None
    etag: str
