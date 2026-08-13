"""Secret-preserving Web configuration for remote Grok2API uploads."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from grok2api_types import normalize_grok2api_account_types
from secure_files import atomic_write_json, exclusive_file_lock
from webui.security_utils import redact_log_line


ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(os.environ.get("GROK2API_CONFIG_FILE", str(ROOT / "config.json")))
LOCK_PATH = CONFIG_PATH.with_suffix(CONFIG_PATH.suffix + ".lock")
MAX_VALUE_LENGTH = 2048


class Grok2APIConfigError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _read_unlocked() -> tuple[dict, str]:
    if not CONFIG_PATH.exists():
        return {}, ""
    try:
        value = json.loads(CONFIG_PATH.read_text(encoding="utf-8") or "{}")
        if not isinstance(value, dict):
            raise ValueError("config.json 必须是 JSON 对象")
        return value, ""
    except Exception as exc:
        return {}, redact_log_line(str(exc))[:240]


def _text(value: object, *, strip: bool = True) -> str:
    result = str(value or "")
    if any(ord(char) < 32 for char in result):
        raise Grok2APIConfigError("配置值包含非法控制字符")
    result = result.strip() if strip else result
    if len(result) > MAX_VALUE_LENGTH:
        raise Grok2APIConfigError("配置值过长")
    return result


def _url(value: object) -> str:
    result = _text(value).rstrip("/")
    if not result:
        return ""
    parsed = urlparse(result)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise Grok2APIConfigError("远程地址必须是有效的 HTTP 或 HTTPS URL")
    if parsed.username or parsed.password:
        raise Grok2APIConfigError("远程地址中不能包含账号密码")
    return result


def _account_types(value: object) -> list[str]:
    try:
        return list(normalize_grok2api_account_types(value))
    except ValueError as exc:
        raise Grok2APIConfigError(str(exc)) from exc


def _public(raw: dict, error: str = "") -> dict:
    try:
        mtime = CONFIG_PATH.stat().st_mtime
    except OSError:
        mtime = None
    remote_url = str(raw.get("grok2api_remote_url") or "")
    username = str(raw.get("grok2api_admin_username") or "")
    has_password = bool(raw.get("grok2api_admin_password"))
    try:
        account_types = _account_types(raw.get("grok2api_account_types"))
    except ValueError as exc:
        account_types = ["grok_build"]
        error = error or redact_log_line(str(exc))[:240]
    return {
        "ok": not error,
        "error": error or None,
        "enabled": bool(raw.get("cpa_auto_add")),
        "remote_url": remote_url,
        "username": username,
        "account_types": account_types,
        "password_configured": has_password,
        "configured": bool(remote_url and username and has_password),
        "config_exists": CONFIG_PATH.exists(),
        "mtime": mtime,
    }


def read_grok2api_config() -> dict:
    with exclusive_file_lock(LOCK_PATH):
        raw, error = _read_unlocked()
    return _public(raw, error)


def _candidate(raw: dict, values: object, clear_password: object = False) -> dict:
    if not isinstance(values, dict):
        raise Grok2APIConfigError("settings 必须是 JSON 对象")
    allowed = {"enabled", "remote_url", "username", "password", "account_types"}
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise Grok2APIConfigError(f"包含不支持的配置字段: {unknown[0]}")
    updated = dict(raw)
    if "enabled" in values:
        if not isinstance(values["enabled"], bool):
            raise Grok2APIConfigError("enabled 必须是布尔值")
        updated["cpa_auto_add"] = values["enabled"]
    if "remote_url" in values:
        updated["grok2api_remote_url"] = _url(values["remote_url"])
    if "username" in values:
        updated["grok2api_admin_username"] = _text(values["username"])
    if "account_types" in values:
        updated["grok2api_account_types"] = _account_types(values["account_types"])
    if values.get("password"):
        updated["grok2api_admin_password"] = _text(values["password"], strip=False)
    if clear_password is True:
        updated["grok2api_admin_password"] = ""
    elif clear_password not in (False, None):
        raise Grok2APIConfigError("clear_password 必须是布尔值")
    return updated


def save_grok2api_config(values: object, *, clear_password: object = False) -> dict:
    with exclusive_file_lock(LOCK_PATH):
        raw, error = _read_unlocked()
        if error:
            raise RuntimeError(f"config.json 无法读取: {error}")
        updated = _candidate(raw, values, clear_password)
        atomic_write_json(CONFIG_PATH, updated)
    result = _public(updated)
    result["saved_at"] = _now()
    return result


def test_grok2api_config(values: object, *, clear_password: object = False, http_post=None) -> dict:
    with exclusive_file_lock(LOCK_PATH):
        raw, error = _read_unlocked()
    if error:
        raise RuntimeError(f"config.json 无法读取: {error}")
    candidate = _candidate(raw, values, clear_password)
    url = str(candidate.get("grok2api_remote_url") or "")
    username = str(candidate.get("grok2api_admin_username") or "")
    password = str(candidate.get("grok2api_admin_password") or "")
    if not url or not username or not password:
        raise Grok2APIConfigError("请填写远程地址、管理员账号和密码")
    if http_post is None:
        import requests

        http_post = requests.post
    try:
        response = http_post(
            f"{url}/api/admin/v1/auth/login",
            json={"username": username, "password": password},
            timeout=15,
        )
        if int(response.status_code) >= 400:
            return {"ok": False, "detail": f"Grok2API 登录失败 HTTP {response.status_code}", "checked_at": _now()}
        token = str(response.json()["data"]["tokens"]["accessToken"] or "")
        if not token:
            raise ValueError("missing accessToken")
    except Grok2APIConfigError:
        raise
    except Exception as exc:
        return {"ok": False, "detail": redact_log_line(str(exc))[:240], "checked_at": _now()}
    return {"ok": True, "detail": "Grok2API 管理员登录成功", "checked_at": _now()}
