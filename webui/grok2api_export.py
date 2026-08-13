"""Build token-protected Grok2API account import downloads from local auth files."""

from __future__ import annotations

import io
import json
import os
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from grok2api_types import (
    GROK2API_ACCOUNT_TYPE_LABELS,
    normalize_grok2api_account_types,
)


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
    content_type: str


def _read_config() -> dict:
    if not CONFIG_PATH.is_file():
        return {}
    try:
        raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8") or "{}")
    except Exception as exc:
        raise Grok2APIExportError("config.json 无法读取") from exc
    if not isinstance(raw, dict):
        raise Grok2APIExportError("config.json 必须是 JSON 对象")
    return raw


def _configured_auth_dir(raw: dict | None = None) -> Path:
    raw = _read_config() if raw is None else raw
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


def _build_import_record(entry: dict, *, source: str) -> dict:
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


def _entries_from_document(value: object, *, source: str) -> list[tuple[dict, str]]:
    if not isinstance(value, dict):
        raise Grok2APIExportError(f"{source} 必须是 JSON 对象")

    accounts = value.get("accounts")
    if accounts is not None:
        if not isinstance(accounts, list):
            raise Grok2APIExportError(f"{source} 的 accounts 必须是数组")
        records: list[tuple[dict, str]] = []
        for index, entry in enumerate(accounts, start=1):
            if not isinstance(entry, dict):
                raise Grok2APIExportError(f"{source} 第 {index} 个账号必须是 JSON 对象")
            records.append((entry, f"{source} 第 {index} 个账号"))
        return records

    if any(key in value for key in ("access_token", "key", "refresh_token")):
        return [(value, source)]

    records: list[tuple[dict, str]] = []
    for entry in value.values():
        if not isinstance(entry, dict):
            continue
        if not any(key in entry for key in ("access_token", "key", "refresh_token")):
            continue
        records.append((entry, source))
    if not records:
        raise Grok2APIExportError(f"{source} 没有可导出的 Grok2API auth")
    return records


def _normalize_sso(value: object) -> str:
    result = _text(value)
    if result.lower().startswith("sso="):
        result = result[4:].strip()
    return result


def _account_sso_by_email() -> dict[str, str]:
    root = CONFIG_PATH.parent / "accounts"
    if not root.is_dir():
        return {}
    excluded = {
        "mail_credentials.txt",
        "sso_pending.txt",
        "sso_risk_rejected.txt",
        "sso_bfs_flagged.txt",
    }
    result: dict[str, str] = {}
    for path in sorted(root.glob("*.txt")):
        if path.name in excluded or not path.is_file():
            continue
        try:
            if path.stat().st_size > MAX_AUTH_FILE_BYTES:
                continue
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            continue
        for line in lines:
            parts = [part.strip() for part in line.split("----")]
            if len(parts) < 3:
                continue
            email = parts[0].lower()
            sso = _normalize_sso(parts[-1])
            if email and len(sso) >= 24 and not any(char.isspace() for char in sso):
                result[email] = sso
    return result


def _sso_import_record(
    provider: str,
    entry: dict,
    *,
    source: str,
    sso_by_email: dict[str, str],
) -> dict:
    email = _text(entry.get("email"))
    user_id = _text(entry.get("user_id") or entry.get("sub"))
    sso = _normalize_sso(entry.get("sso_token") or entry.get("sso"))
    if not sso and email:
        sso = sso_by_email.get(email.lower(), "")
    if not sso:
        label = GROK2API_ACCOUNT_TYPE_LABELS[provider]
        raise Grok2APIExportError(f"{source} 缺少 {label} 导入所需的 SSO")
    label = GROK2API_ACCOUNT_TYPE_LABELS[provider]
    record = {
        "provider": provider,
        "name": _text(entry.get("name")) or email or user_id or f"Grok {label} account",
        "email": email,
        "user_id": user_id,
        "sso_token": sso,
    }
    if provider == "grok_web":
        record["tier"] = "auto"
    proxy_url = _text(
        entry.get("proxy_url") or entry.get("proxy") or entry.get("proxyUrl")
    )
    if proxy_url:
        record["proxy_url"] = proxy_url
    return record


def _json_document(provider: str, records: list[dict], *, wrapped: bool) -> bytes:
    value: dict = {"accounts": records}
    if wrapped:
        value = {"provider": provider, "accounts": records}
    return json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"


def _zip_documents(documents: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in documents.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, content)
    return output.getvalue()


def build_grok2api_export(now: datetime | None = None) -> Grok2APIExport:
    """Return one JSON or a provider-separated ZIP import download."""
    config = _read_config()
    try:
        account_types = normalize_grok2api_account_types(
            config.get("grok2api_account_types")
        )
    except ValueError as exc:
        raise Grok2APIExportError(str(exc)) from exc
    auth_dir = _configured_auth_dir(config)
    if not auth_dir.is_dir():
        raise Grok2APIExportEmptyError("没有本地 Grok2API auth 可下载")

    paths = sorted(path for path in auth_dir.glob("g2a-*.json") if path.is_file())
    if not paths:
        raise Grok2APIExportEmptyError("没有本地 Grok2API auth 可下载")

    entries: list[tuple[dict, str]] = []
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
        entries.extend(_entries_from_document(value, source=path.name))
        if len(entries) * len(account_types) > MAX_EXPORT_ACCOUNTS:
            raise Grok2APIExportError(
                f"单次最多导出 {MAX_EXPORT_ACCOUNTS} 个账号"
            )

    if not entries:
        raise Grok2APIExportEmptyError("没有本地 Grok2API auth 可下载")
    sso_by_email = (
        _account_sso_by_email()
        if any(provider != "grok_build" for provider in account_types)
        else {}
    )
    records_by_provider: dict[str, list[dict]] = {
        provider: [] for provider in account_types
    }
    for entry, source in entries:
        for provider in account_types:
            if provider == "grok_build":
                record = _build_import_record(entry, source=source)
            else:
                record = _sso_import_record(
                    provider,
                    entry,
                    source=source,
                    sso_by_email=sso_by_email,
                )
            records_by_provider[provider].append(record)

    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%d-%H%M%S")
    if len(account_types) == 1:
        provider = account_types[0]
        suffix = "accounts" if provider == "grok_build" else f"{provider.removeprefix('grok_')}-accounts"
        return Grok2APIExport(
            filename=f"grok2api-{suffix}-{stamp}.json",
            content=_json_document(
                provider,
                records_by_provider[provider],
                wrapped=provider != "grok_build",
            ),
            account_count=len(records_by_provider[provider]),
            content_type="application/json",
        )

    documents = {
        f"grok2api-{provider.removeprefix('grok_')}-accounts.json": _json_document(
            provider,
            records_by_provider[provider],
            wrapped=True,
        )
        for provider in account_types
    }
    return Grok2APIExport(
        filename=f"grok2api-accounts-{stamp}.zip",
        content=_zip_documents(documents),
        account_count=sum(len(records) for records in records_by_provider.values()),
        content_type="application/zip",
    )
