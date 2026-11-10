"""Parse `terraform show -json` plan output into a flat list of changes."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

# Display order: the most dangerous kind of change comes first.
KINDS = ("destroy", "replace", "update", "create")


class PlanError(ValueError):
    """The input is not a usable Terraform plan JSON document."""


@dataclass
class Change:
    address: str
    type: str
    kind: str  # one of KINDS
    before: dict[str, Any] = field(default_factory=dict)
    after: dict[str, Any] = field(default_factory=dict)
    replace_paths: list[str] = field(default_factory=list)
    create_before_destroy: bool = False


def _kind(actions: list[str]) -> str | None:
    """Map Terraform's action list to one kind, or None for nothing to do."""
    acts = set(actions)
    if {"create", "delete"} <= acts:
        return "replace"
    if "delete" in acts:
        return "destroy"
    if "update" in acts:
        return "update"
    if "create" in acts:
        return "create"
    return None  # no-op, read, forget


def _path_to_str(path: Any) -> str:
    if not isinstance(path, list):
        return str(path)
    out = ""
    for part in path:
        out += f"[{part}]" if isinstance(part, int) else (f".{part}" if out else str(part))
    return out


def parse_plan(text: str) -> list[Change]:
    """Return the managed-resource changes in a plan, skipping no-ops and data reads."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PlanError(f"input is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or "format_version" not in doc:
        raise PlanError(
            "input does not look like `terraform show -json` output "
            "(no top-level format_version)"
        )
    if "resource_changes" not in doc and "values" in doc:
        raise PlanError(
            "this is state JSON, not a plan; run `terraform show -json <planfile>`"
        )

    changes: list[Change] = []
    for rc in doc.get("resource_changes") or []:
        if rc.get("mode", "managed") != "managed":
            continue
        ch = rc.get("change") or {}
        actions = ch.get("actions") or []
        kind = _kind(actions)
        if kind is None:
            continue
        changes.append(
            Change(
                address=rc.get("address", "<unknown>"),
                type=rc.get("type", ""),
                kind=kind,
                before=ch.get("before") or {},
                after=ch.get("after") or {},
                replace_paths=[_path_to_str(p) for p in ch.get("replace_paths") or []],
                create_before_destroy=actions[:1] == ["create"] and kind == "replace",
            )
        )
    return changes


def group_by_kind(changes: list[Change]) -> dict[str, list[Change]]:
    groups: dict[str, list[Change]] = {k: [] for k in KINDS}
    for c in changes:
        groups[c.kind].append(c)
    for items in groups.values():
        items.sort(key=lambda c: c.address)
    return groups
