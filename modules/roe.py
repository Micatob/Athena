"""RoE loader (thin wrapper over hard_guardrail.RoE)."""
import json
from typing import Any, Dict
from .hard_guardrail import RoE, hard_guardrail_reason, is_hard_blocked  # noqa: F401


def load_roe_file(path: str) -> RoE:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return RoE()
        return RoE.from_dict(data)
    except Exception:
        return RoE()


def roe_status(roe: RoE) -> Dict[str, Any]:
    return {
        "engagement_id": roe.engagement_id,
        "targets": list(roe.targets),
        "exclusions": list(roe.exclusions),
        "allowed_techniques": list(roe.allowed_techniques),
        "max_rps": roe.max_rps,
        "window": {"not_before": roe.not_before, "not_after": roe.not_after},
    }
