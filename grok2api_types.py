"""Shared Grok2API provider selection rules."""

from __future__ import annotations


GROK2API_ACCOUNT_TYPES = ("grok_build", "grok_web", "grok_console")
DEFAULT_GROK2API_ACCOUNT_TYPES = ("grok_build",)
GROK2API_ACCOUNT_TYPE_LABELS = {
    "grok_build": "Build",
    "grok_web": "Web",
    "grok_console": "Console",
}


def normalize_grok2api_account_types(
    value: object,
    *,
    default: tuple[str, ...] = DEFAULT_GROK2API_ACCOUNT_TYPES,
) -> tuple[str, ...]:
    """Validate and return provider values in the stable display order."""
    if value is None:
        return tuple(default)
    if not isinstance(value, (list, tuple)):
        raise ValueError("account_types 必须是数组")
    requested: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise ValueError("account_types 只能包含字符串")
        provider = item.strip().lower()
        if provider not in GROK2API_ACCOUNT_TYPES:
            raise ValueError(f"不支持的 Grok2API 账号类型: {provider or '(空)'}")
        requested.add(provider)
    if not requested:
        raise ValueError("至少选择一种 Grok2API 账号类型")
    return tuple(item for item in GROK2API_ACCOUNT_TYPES if item in requested)
