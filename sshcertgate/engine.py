"""Verify entry point. Not implemented in this snapshot."""

from __future__ import annotations

from typing import Any


def verify(
    cert_text: bytes,
    trust: dict[str, Any],
    *,
    principal: str,
    cert_type: str,
    source_address: str | None,
    command: str | None,
    now: int,
) -> dict[str, Any]:
    raise NotImplementedError("verify is not implemented in this snapshot")
