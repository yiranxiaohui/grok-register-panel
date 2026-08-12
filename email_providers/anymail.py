"""AnyMail domain mailbox provider.

API contract (see the sibling ``any-mail`` repository):

- ``GET /api/domains`` lists domains owned by the API-key user.
- ``POST /api/accounts`` creates a ``provider=domain`` mailbox.
- ``GET /api/emails/latest`` polls messages for one recipient.
- ``DELETE /api/accounts/:id`` removes the mailbox and its messages.

Authentication uses ``Authorization: Bearer ak_...``.  The key must be bound
to ``provider=domain`` and have ``emails:read`` plus ``accounts:write``;
``domains:read`` is also needed when no fixed domain is configured.
"""

from __future__ import annotations

import re
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, List, Optional, Tuple
from urllib.parse import urlparse

from email_providers.common import extract_verification_code, generate_username

HttpGet = Callable[..., Any]
HttpPost = Callable[..., Any]
HttpDelete = Callable[..., Any]

DEFAULT_EXPIRY_MS = 3_600_000

_domain_cache: List[str] = []
_domain_cache_key: Optional[Tuple[str, str]] = None
_domain_index = 0
_domain_lock = threading.Lock()


class AnyMailAPIError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = int(status_code or 0)
        super().__init__(message)


def reset_runtime_state() -> None:
    global _domain_cache, _domain_cache_key, _domain_index
    with _domain_lock:
        _domain_cache = []
        _domain_cache_key = None
        _domain_index = 0


def normalize_base(base_url: str = "") -> str:
    """Return the AnyMail site root, accepting an accidental trailing /api."""
    raw = str(base_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    path = (parsed.path or "").rstrip("/")
    if path.endswith("/api"):
        path = path[: -len("/api")].rstrip("/")
    return f"{origin}{path}" if path else origin


def _api(base_url: str, path: str) -> str:
    path = path if path.startswith("/") else f"/{path}"
    return f"{normalize_base(base_url)}{path}"


def _headers(api_key: str, *, content_type: bool = False) -> dict:
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {str(api_key or '').strip()}",
    }
    if content_type:
        headers["Content-Type"] = "application/json"
    return headers


def _parse_json(response, action: str) -> Any:
    try:
        return response.json()
    except Exception as exc:
        preview = str(getattr(response, "text", "") or "")[:300]
        raise Exception(f"AnyMail {action}返回非 JSON: {preview}") from exc


def _raise_http(response, action: str) -> None:
    status = int(getattr(response, "status_code", 0) or 0)
    if status < 400:
        return
    try:
        payload = response.json()
        if isinstance(payload, dict):
            detail = str(payload.get("error") or payload.get("message") or payload)[:300]
        else:
            detail = str(payload)[:300]
    except Exception:
        detail = str(getattr(response, "text", "") or "")[:300]
    raise AnyMailAPIError(
        status,
        f"AnyMail {action}失败 HTTP {status}: {detail or 'unknown'}",
    )


def list_domains(
    http_get: HttpGet,
    base_url: str,
    api_key: str,
    *,
    force_refresh: bool = False,
) -> List[str]:
    global _domain_cache, _domain_cache_key
    base = normalize_base(base_url)
    key = str(api_key or "").strip()
    cache_key = (base, key)
    with _domain_lock:
        if not force_refresh and _domain_cache and _domain_cache_key == cache_key:
            return list(_domain_cache)

    response = http_get(
        _api(base, "/api/domains"),
        headers=_headers(key),
        timeout=15,
        proxies={},
    )
    _raise_http(response, "获取域名")
    payload = _parse_json(response, "获取域名")
    rows = payload.get("domains") if isinstance(payload, dict) else None
    domains: List[str] = []
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                value = row.get("name") or row.get("domain_name") or row.get("domain")
            else:
                value = row
            domain = str(value or "").strip().lower().lstrip("@")
            if domain and domain not in domains:
                domains.append(domain)

    with _domain_lock:
        _domain_cache = domains
        _domain_cache_key = cache_key
    return list(domains)


def _expiry_iso(expiry_ms: int) -> Optional[str]:
    try:
        value = int(expiry_ms)
    except (TypeError, ValueError):
        value = DEFAULT_EXPIRY_MS
    if value <= 0:
        return None
    expires = datetime.now(timezone.utc) + timedelta(milliseconds=value)
    return expires.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def create_mailbox(
    http_get: HttpGet,
    http_post: HttpPost,
    base_url: str,
    api_key: str,
    *,
    domain: str = "",
    name: str = "",
    expiry_ms: int = DEFAULT_EXPIRY_MS,
) -> Tuple[str, str]:
    """Create an AnyMail domain mailbox and return ``(address, account_id)``."""
    global _domain_index
    base = normalize_base(base_url)
    key = str(api_key or "").strip()
    if not base:
        raise Exception("AnyMail 站点 URL 未配置（anymail_api_base）")
    if not key:
        raise Exception("AnyMail API Key 未配置（anymail_api_key）")

    selected_domain = str(domain or "").strip().lower().lstrip("@")
    if not selected_domain:
        domains = list_domains(http_get, base, key)
        if not domains:
            raise Exception(
                "AnyMail 无可用域名：请配置 anymail_domain，"
                "或为 API Key 添加 domains:read 后在 AnyMail 声明域名"
            )
        with _domain_lock:
            selected_domain = domains[_domain_index % len(domains)]
            _domain_index += 1

    expires_at = _expiry_iso(expiry_ms)
    preferred_name = str(name or "").strip()
    last_error: Optional[Exception] = None
    for attempt in range(4):
        local_part = preferred_name if preferred_name and attempt == 0 else generate_username(12)
        address = f"{local_part}@{selected_domain}"
        response = http_post(
            _api(base, "/api/accounts"),
            json={"email": address, "expires_at": expires_at},
            headers=_headers(key, content_type=True),
            timeout=20,
            proxies={},
        )
        status = int(getattr(response, "status_code", 0) or 0)
        if status == 409 and attempt < 3:
            last_error = Exception("AnyMail 邮箱地址已存在")
            continue
        _raise_http(response, "创建邮箱")
        payload = _parse_json(response, "创建邮箱")
        account = payload.get("account") if isinstance(payload, dict) else None
        if not isinstance(account, dict):
            raise Exception("AnyMail 创建邮箱响应缺少 account")
        account_id = str(account.get("id") or "").strip()
        created_address = str(account.get("email") or address).strip()
        if not account_id or not created_address:
            raise Exception("AnyMail 创建邮箱响应缺少 id 或 email")
        print(f"[AnyMail] 创建邮箱成功: {created_address}")
        return created_address, account_id
    raise Exception("AnyMail 创建邮箱失败（地址冲突重试耗尽）") from last_error


def get_latest_messages(
    http_get: HttpGet,
    base_url: str,
    api_key: str,
    email: str,
) -> List[dict]:
    response = http_get(
        _api(base_url, "/api/emails/latest"),
        headers=_headers(api_key),
        params={"to": str(email or "").strip(), "limit": 10},
        timeout=20,
        proxies={},
    )
    _raise_http(response, "获取邮件")
    payload = _parse_json(response, "获取邮件")
    rows = payload.get("emails") if isinstance(payload, dict) else None
    return [row for row in (rows or []) if isinstance(row, dict)]


def delete_mailbox(
    http_delete: HttpDelete,
    base_url: str,
    api_key: str,
    account_id: str,
) -> None:
    if not account_id:
        return
    response = http_delete(
        _api(base_url, f"/api/accounts/{account_id}"),
        headers=_headers(api_key),
        timeout=15,
        proxies={},
    )
    status = int(getattr(response, "status_code", 0) or 0)
    if status >= 400 and status != 404:
        _raise_http(response, "删除邮箱")


def _message_text(message: dict) -> Tuple[str, str]:
    subject = str(message.get("subject") or "")
    parts = []
    for field in ("text_body", "html_body", "text", "html", "body", "content"):
        value = message.get(field)
        if isinstance(value, str) and value.strip():
            parts.append(re.sub(r"<[^>]+>", " ", value))
    return subject, "\n".join(parts)


def wait_for_code(
    http_get: HttpGet,
    base_url: str,
    api_key: str,
    account_id: str,
    email: str,
    *,
    timeout: int = 180,
    poll_interval: int = 3,
    http_delete: Optional[HttpDelete] = None,
    cleanup: bool = True,
    raise_if_cancelled: Callable[[Optional[Callable[[], bool]]], None],
    sleep_with_cancel: Callable[[float, Optional[Callable[[], bool]]], None],
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
    resend_callback: Optional[Callable[[], None]] = None,
) -> str:
    """Poll AnyMail until an xAI verification code is found."""
    base = normalize_base(base_url)
    key = str(api_key or "").strip()
    mailbox_id = str(account_id or "").strip()
    address = str(email or "").strip()
    if not base:
        raise Exception("AnyMail 站点 URL 未配置")
    if not key:
        raise Exception("AnyMail API Key 未配置")
    if not address:
        raise Exception("AnyMail 邮箱地址为空，无法收信")

    deadline = time.time() + timeout
    next_resend_at = time.time() + 35
    try:
        while time.time() < deadline:
            raise_if_cancelled(cancel_callback)
            if resend_callback and time.time() >= next_resend_at:
                try:
                    resend_callback()
                    if log_callback:
                        log_callback("[*] 已触发重新发送验证码")
                except Exception as exc:
                    if log_callback:
                        log_callback(f"[Debug] 触发重发验证码失败: {exc}")
                next_resend_at = time.time() + 35

            try:
                messages = get_latest_messages(http_get, base, key, address)
            except AnyMailAPIError as exc:
                if exc.status_code in (401, 403):
                    raise
                if log_callback:
                    log_callback(f"[Debug] AnyMail 拉取邮件失败: {exc}")
                sleep_with_cancel(poll_interval, cancel_callback)
                continue
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] AnyMail 拉取邮件失败: {exc}")
                sleep_with_cancel(poll_interval, cancel_callback)
                continue

            if log_callback:
                log_callback(f"[Debug] AnyMail 本轮邮件数量: {len(messages)}")
            for message in messages:
                subject, content = _message_text(message)
                code = extract_verification_code(content, subject)
                if code:
                    if log_callback:
                        log_callback("[*] AnyMail 已提取到验证码")
                    return code
            sleep_with_cancel(poll_interval, cancel_callback)
        raise Exception(f"AnyMail 在 {timeout}s 内未收到验证码邮件")
    finally:
        if cleanup and http_delete is not None and mailbox_id:
            try:
                delete_mailbox(http_delete, base, key, mailbox_id)
                print(f"[AnyMail] 已删除临时邮箱: {address}")
            except Exception as exc:
                print(f"[AnyMail] 删除邮箱失败: {address} -> {exc}")
