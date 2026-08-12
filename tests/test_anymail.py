# -*- coding: utf-8 -*-
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import connectivity
from email_providers import anymail


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code
        self.text = str(payload)

    def json(self):
        return self.payload


def test_normalize_base():
    assert anymail.normalize_base("mail.example.com/api") == "https://mail.example.com"
    assert anymail.normalize_base("https://mail.example.com/api/") == "https://mail.example.com"
    assert anymail.normalize_base("https://host.example/prefix/api") == "https://host.example/prefix"


def test_domain_discovery_rotation_and_create_contract():
    anymail.reset_runtime_state()
    calls = []

    def http_get(url, **kwargs):
        calls.append(("GET", url, kwargs))
        assert kwargs["headers"]["Authorization"] == "Bearer ak_example_not_real"
        assert kwargs["proxies"] == {}
        return FakeResponse({"domains": [{"name": "one.example"}, {"name": "two.example"}]})

    def http_post(url, **kwargs):
        calls.append(("POST", url, kwargs))
        assert kwargs["headers"]["Authorization"] == "Bearer ak_example_not_real"
        assert kwargs["proxies"] == {}
        address = kwargs["json"]["email"]
        assert kwargs["json"]["expires_at"].endswith("Z")
        return FakeResponse(
            {"ok": True, "account": {"id": f"id-{address}", "email": address}},
            status_code=201,
        )

    first = anymail.create_mailbox(
        http_get,
        http_post,
        "https://mail.example/api",
        "ak_example_not_real",
        name="user",
    )
    second = anymail.create_mailbox(
        http_get,
        http_post,
        "https://mail.example",
        "ak_example_not_real",
        name="user",
    )

    assert first == ("user@one.example", "id-user@one.example")
    assert second == ("user@two.example", "id-user@two.example")
    assert [method for method, _, _ in calls].count("GET") == 1


def test_fixed_domain_and_collision_retry():
    post_count = 0

    def http_get(*_args, **_kwargs):
        raise AssertionError("fixed domain must not require domains:read")

    def http_post(_url, **kwargs):
        nonlocal post_count
        post_count += 1
        if post_count == 1:
            return FakeResponse({"error": "this address is already claimed"}, 409)
        address = kwargs["json"]["email"]
        return FakeResponse({"account": {"id": "account-id", "email": address}}, 201)

    address, account_id = anymail.create_mailbox(
        http_get,
        http_post,
        "https://mail.example",
        "ak_example_not_real",
        domain="fixed.example",
        name="already-used",
        expiry_ms=0,
    )

    assert address.endswith("@fixed.example")
    assert address != "already-used@fixed.example"
    assert account_id == "account-id"
    assert post_count == 2


def test_wait_for_code_and_cleanup():
    deleted = []

    def http_get(url, **kwargs):
        assert url == "https://mail.example/api/emails/latest"
        assert kwargs["params"]["to"] == "user@example.com"
        assert kwargs["proxies"] == {}
        return FakeResponse(
            {
                "emails": [
                    {
                        "subject": "Your xAI verification code",
                        "text_body": "Use A99-698 to continue.",
                        "html_body": "",
                    }
                ]
            }
        )

    def http_delete(url, **kwargs):
        assert kwargs["proxies"] == {}
        deleted.append(url)
        return FakeResponse({"ok": True})

    code = anymail.wait_for_code(
        http_get,
        "https://mail.example",
        "ak_example_not_real",
        "account-id",
        "user@example.com",
        http_delete=http_delete,
        raise_if_cancelled=lambda callback: None,
        sleep_with_cancel=lambda seconds, callback: None,
    )

    assert code == "A99-698"
    assert deleted == ["https://mail.example/api/accounts/account-id"]


def test_wait_for_code_fails_fast_on_scope_error():
    calls = 0

    def http_get(_url, **_kwargs):
        nonlocal calls
        calls += 1
        return FakeResponse({"error": "missing required scope: emails:read"}, 403)

    try:
        anymail.wait_for_code(
            http_get,
            "https://mail.example",
            "ak_example_not_real",
            "account-id",
            "user@example.com",
            cleanup=False,
            raise_if_cancelled=lambda callback: None,
            sleep_with_cancel=lambda seconds, callback: None,
        )
    except anymail.AnyMailAPIError as exc:
        assert exc.status_code == 403
        assert "emails:read" in str(exc)
    else:
        raise AssertionError("scope errors must fail immediately")
    assert calls == 1


def test_connectivity_probe():
    seen = []

    def http_get(url, **kwargs):
        seen.append((url, kwargs))
        return FakeResponse({"domains": [{"name": "mail.example"}]})

    result = connectivity.check_email_api(
        "anymail",
        {
            "anymail_api_base": "https://mail.example/api",
            "anymail_api_key": "ak_example_not_real",
        },
        http_get,
        lambda *args, **kwargs: None,
    )

    assert result[1] is True
    assert "mail.example" in result[2]
    assert seen[0][0] == "https://mail.example/api/domains"
    assert seen[0][1]["headers"]["Authorization"] == "Bearer ak_example_not_real"
    assert seen[0][1]["proxies"] == {}

    fixed = connectivity.check_email_api(
        "anymail",
        {
            "anymail_api_base": "https://mail.example",
            "anymail_api_key": "ak_example_not_real",
            "anymail_domain": "fixed.example",
        },
        http_get,
        lambda *args, **kwargs: None,
    )
    assert fixed[1] is True
    assert seen[1][0] == "https://mail.example/api/emails/latest"
    assert seen[1][1]["params"] == {"to": "probe@fixed.example", "limit": 1}


if __name__ == "__main__":
    test_normalize_base()
    test_domain_discovery_rotation_and_create_contract()
    test_fixed_domain_and_collision_retry()
    test_wait_for_code_and_cleanup()
    test_wait_for_code_fails_fast_on_scope_error()
    test_connectivity_probe()
    print("OK anymail")
