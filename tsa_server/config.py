"""Runtime configuration, sourced from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


DEFAULT_POLICY_OID = "1.3.6.1.4.1.55555.1.1"


@dataclass(frozen=True)
class Config:
    data_dir: Path
    policy_oid: str
    max_request_bytes: int
    max_concurrency: int
    sign_timeout_seconds: float
    accuracy_seconds: int

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            data_dir=Path(os.environ.get("TSA_DATA_DIR", "data")),
            policy_oid=os.environ.get("TSA_POLICY_OID", DEFAULT_POLICY_OID),
            max_request_bytes=int(os.environ.get("TSA_MAX_REQUEST_BYTES", "16384")),
            max_concurrency=int(os.environ.get("TSA_MAX_CONCURRENCY", "4")),
            sign_timeout_seconds=float(os.environ.get("TSA_SIGN_TIMEOUT", "5")),
            accuracy_seconds=int(os.environ.get("TSA_ACCURACY_SECONDS", "1")),
        )

