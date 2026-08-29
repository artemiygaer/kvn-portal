"""Чистые операции над семантическим состоянием."""

import hashlib
import json

def state_revision(state: dict) -> str:
    """Стабильная ревизия семантического содержимого JSON."""
    canonical = json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
