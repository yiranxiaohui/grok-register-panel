"""Build token-protected Grok2API account import downloads from local auth files."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(os.environ.get("GROK2API_CONFIG_FILE", str(ROOT / "config.json")))
DEFAULT_AUTH_DIR = Path(
    os.environ.get("GROK2API_AUTH_DIR", str(ROOT / "grok2api_auth"))
)
MAX_AUTH_FILE_BYTES = 8 * 1024 * 1024
MAX_EXPORT_ACCOUNTS = 10_000


class Grok2APIExportError(ValueError):
    """The configured local auth data cannot be exported safely."""


class Grok2APIExportEmptyError(Grok2APIExportError):
    """No local Grok2API auth records are available."""


@dataclass(frozen=True)
class Grok2APIExport:
    filename: str
    content: bytes
    account_count: int


def _configured_auth_dir() -> Path:
    configured = ""
    if CONFIG_PATH.is_file():
        try:
            raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8") or "{}")
        except Exception as exc:
            raise Grok2APIExportError("config.json 无法读取") from exc
        if not isinstance(raw, dict):
            raise Grok2APIExportError("config.json 必须是 JSON 对象")
        configured = str(raw.get("grok2api_auth_dir") or "").strip()
    if not configured:
        return DEFAULT_AUTH_DIR
    result = Path(configured).expanduser()
    if not result.is_absolute():
        result = CONFIG_PATH.parent / result
    return result


def _text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float)):
        return str(value).strip()
    return ""


def _import_record(entry: dict, *, source: str) -> dict:
    access_token = _text(entry.get("access_token") or entry.get("key"))
    refresh_token = _text(entry.get("refresh_token"))
    if not access_token and not refresh_token:
        raise Grok2APIExportError(f"{source} 缺少 access_token 和 refresh_token")

    email = _text(entry.get("email"))
    user_id = _text(entry.get("user_id") or entry.get("sub"))
    principal_id = _text(entry.get("principal_id") or user_id)
    record = {
        "provider": "grok_build",
        "name": _text(entry.get("name")) or email or user_id or "Grok Build account",
        "client_id": _text(entry.get("client_id") or entry.get("oidc_client_id")),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "id_token": _text(entry.get("id_token")),
        "token_type": _text(entry.get("token_type")) or "Bearer",
        "scope": _text(entry.get("scope")),
        "expires_at": _text(entry.get("expires_at")),
        "email": email,
        "user_id": user_id,
        "principal_id": principal_id,
    }
    team_id = _text(entry.get("team_id"))
    if team_id:
        record["team_id"] = team_id
    proxy_url = _text(
        entry.get("proxy_url") or entry.get("proxy") or entry.get("proxyUrl")
    )
    if proxy_url:
        record["proxy_url"] = proxy_url
    return record


def _records_from_document(value: object, *, source: str) -> list[dict]:
    if not isinstance(value, dict):
        raise Grok2APIExportError(f"{source} 必须是 JSON 对象")

    accounts = value.get("accounts")
    if accounts is not None:
        if not isinstance(accounts, list):
            raise Grok2APIExportError(f"{source} 的 accounts 必须是数组")
        records = []
        for index, entry in enumerate(accounts, start=1):
            if not isinstance(entry, dict):
                raise Grok2APIExportError(f"{source} 第 {index} 个账号必须是 JSON 对象")
            records.append(
                _import_record(entry, source=f"{source} 第 {index} 个账号")
            )
        return records

    if any(key in value for key in ("access_token", "key", "refresh_token")):
        return [_import_record(value, source=source)]

    records = []
    for entry in value.values():
        if not isinstance(entry, dict):
            continue
        if not any(key in entry for key in ("access_token", "key", "refresh_token")):
            continue
        records.append(_import_record(entry, source=source))
    if not records:
        raise Grok2APIExportError(f"{source} 没有可导出的 Grok2API auth")
    return records


def build_grok2api_export(now: datetime | None = None) -> Grok2APIExport:
    """Return one Grok2API-compatible ``{"accounts": [...]}`` JSON download."""
    auth_dir = _configured_auth_dir()
    if not auth_dir.is_dir():
        raise Grok2APIExportEmptyError("没有本地 Grok2API auth 可下载")

    paths = sorted(path for path in auth_dir.glob("g2a-*.json") if path.is_file())
    if not paths:
        raise Grok2APIExportEmptyError("没有本地 Grok2API auth 可下载")

    records: list[dict] = []
    for path in paths:
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise Grok2APIExportError(f"无法读取 {path.name}") from exc
        if size > MAX_AUTH_FILE_BYTES:
            raise Grok2APIExportError(f"{path.name} 超过导出大小限制")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise Grok2APIExportError(f"{path.name} 不是有效 JSON") from exc
        records.extend(_records_from_document(value, source=path.name))
        if len(records) > MAX_EXPORT_ACCOUNTS:
            raise Grok2APIExportError(
                f"单次最多导出 {MAX_EXPORT_ACCOUNTS} 个账号"
            )

    if not records:
        raise Grok2APIExportEmptyError("没有本地 Grok2API auth 可下载")
    document = json.dumps(
        {"accounts": records}, ensure_ascii=False, indent=2
    ).encode("utf-8") + b"\n"
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%d-%H%M%S")
    return Grok2APIExport(
        filename=f"grok2api-accounts-{stamp}.json",
        content=document,
        account_count=len(records),
    )
